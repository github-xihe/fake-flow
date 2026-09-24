'use strict';
'require baseclass';

// The supported TOML subset matches ebpf/user/config.c. Never evaluate input.
var fields = {
	tcp_enabled: ['bool', true], tcp_directions: ['directions', 'both'],
	tcp_payload: ['enum', 'http', ['http', 'tls', 'custom']],
	tcp_hostname: ['string', 'www.example.com'], tcp_payload_file: ['string', ''],
	tcp_tfo: ['enum', 'strip-syn', ['strip-syn', 'preserve']], tcp_max_batches: ['number', 3, 1, 32],
	udp_enabled: ['bool', true], udp_trigger: ['enum', 'egress', ['egress', 'both']],
	udp_payload: ['enum', 'sip', ['sip', 'custom']], udp_sip_uri: ['string', 'sip:service@example.com'],
	udp_payload_file: ['string', ''], udp_initial_packets: ['number', 5, 1, 32],
	udp_idle_timeout_seconds: ['number', 30, 1, 3600],
	injection_ttl: ['number', 3, 1, 255], injection_repeat: ['number', 2, 1, 8],
	injection_estimate_hops: ['bool', true], injection_dynamic_percent: ['number', 0, 0, 99],
	injection_max_packets_per_second: ['number', 1000, 1, 1000000],
	injection_burst: ['number', 2000, 1, 1000000], injection_allow_private: ['bool', false],
	runtime_tcp_entries: ['number', 8192, 64, 1048576], runtime_udp_entries: ['number', 8192, 64, 1048576],
	runtime_lease_seconds: ['number', 10, 4, 60]
};
function defaults() {
	var values = {};
	Object.keys(fields).forEach(function(k) {
		values[k] = fields[k][0] === 'bool' ? (fields[k][1] ? '1' : '0') : String(fields[k][1]);
	});
	return values;
}
function quote(value) {
	if (typeof value !== 'string' || /["\\\x00-\x1f]/.test(value))
		throw new Error('文本不能包含双引号、反斜杠或换行。');
	return '"' + value + '"';
}
function parse(text) {
	var settings = defaults(), interfaces = [], section = '', seen = {}, sections = {}, version = false;
	text.split(/\r?\n/).forEach(function(raw, index) {
		var quoted = false, line = '';
		for (var i = 0; i < raw.length; i++) {
			if (raw[i] === '"') quoted = !quoted;
			if (raw[i] === '#' && !quoted) break;
			line += raw[i];
		}
		line = line.trim();
		if (!line) return;
		function fail() { throw new Error('第 ' + (index + 1) + ' 行无法转换为表单，请使用 TOML 编辑模式修正。'); }
		if (line === '[[interfaces]]') {
			section = 'interfaces'; interfaces.push({ name: '', mode: 'ethernet' }); return;
		}
		if (/^\[(tcp|udp|injection|runtime)\]$/.test(line)) {
			section = line.slice(1, -1);
			if (sections[section]) fail();
			sections[section] = true; return;
		}
		var match = line.match(/^([a-z_]+)\s*=\s*(.+)$/);
		if (!match) fail();
		var key = match[1], value = match[2], id = section + '.' + interfaces.length + '.' + key;
		if (seen[id]) fail();
		seen[id] = true;
		if (!section && key === 'version' && value === '1') { version = true; return; }
		var spec = section === 'interfaces' && (key === 'name' || key === 'mode') ? ['string'] : fields[section + '_' + key];
		if (!spec) fail();
		var parsed;
		if (spec[0] === 'bool') {
			if (value !== 'true' && value !== 'false') fail();
			parsed = value === 'true' ? '1' : '0';
		} else if (spec[0] === 'number') {
			if (!/^\d+$/.test(value) || +value < spec[2] || +value > spec[3]) fail();
			parsed = value;
		} else if (spec[0] === 'directions') {
			var array;
			try { array = JSON.parse(value); } catch (_) { fail(); }
			if (!Array.isArray(array) || !array.length || array.length > 2 ||
				array.some(function(v) { return v !== 'active' && v !== 'passive'; }) ||
				(array.length === 2 && array[0] === array[1])) fail();
			parsed = array.length === 2 ? 'both' : array[0];
		} else {
			if (!/^"[^"\\\x00-\x1f]*"$/.test(value)) fail();
			parsed = value.slice(1, -1);
			if (spec[0] === 'enum' && spec[2].indexOf(parsed) < 0) fail();
		}
		if (section === 'interfaces') interfaces[interfaces.length - 1][key] = parsed;
		else settings[section + '_' + key] = parsed;
	});
	if (!version || !interfaces.length) throw new Error('需要 version = 1 和至少一个接口。');
	// Validate names and combinations before allowing a form rewrite.
	serialize(settings, interfaces);
	return { settings: settings, interface: interfaces };
}
function serialize(settings, interfaces) {
	if (!interfaces.length || interfaces.length > 8) throw new Error('需要配置 1–8 个接口。');
	var names = Object.create(null), modes = {}, lines = ['version = 1'];
	interfaces.forEach(function(d) {
		if (!/^[A-Za-z0-9_.:-]{1,15}$/.test(d.name) || names[d.name]) throw new Error('接口名称无效或重复。');
		if (['ethernet', 'pppoe', 'l3'].indexOf(d.mode) < 0) throw new Error('接口模式无效。');
		names[d.name] = true; modes[d.mode] = true;
		lines.push('', '[[interfaces]]', 'name = ' + quote(d.name), 'mode = ' + quote(d.mode));
	});
	if (modes.pppoe && modes.l3) throw new Error('同一实例不能同时使用物理 PPPoE 和 L3 模式。');
	if (+settings.injection_burst < +settings.injection_repeat) throw new Error('突发额度不能小于每批副本数。');
	['tcp', 'udp', 'injection', 'runtime'].forEach(function(section) {
		lines.push('', '[' + section + ']');
		Object.keys(fields).forEach(function(id) {
			if (id.indexOf(section + '_') !== 0) return;
			var key = id.slice(section.length + 1), spec = fields[id], value = settings[id];
			if ((section === 'tcp' || section === 'udp') &&
				((key === 'payload_file' && settings[section + '_payload'] !== 'custom') ||
				((key === 'hostname' || key === 'sip_uri') && settings[section + '_payload'] === 'custom'))) return;
			if (spec[0] === 'bool') {
				if (value !== '0' && value !== '1') throw new Error(id + ': 开关值无效。');
				value = value === '1' ? 'true' : 'false';
			} else if (spec[0] === 'number') {
				if (!/^\d+$/.test(String(value)) || +value < spec[2] || +value > spec[3]) throw new Error(id + ': 数值超出范围。');
				value = String(+value);
			} else if (spec[0] === 'directions') {
				if (['active', 'passive', 'both'].indexOf(value) < 0) throw new Error('TCP 方向无效。');
				value = value === 'both' ? '["active", "passive"]' : '[' + quote(value) + ']';
			} else {
				if (spec[0] === 'enum' && spec[2].indexOf(value) < 0) throw new Error(id + ': 选项无效。');
				value = quote(value);
			}
			lines.push(key + ' = ' + value);
		});
	});
	return lines.join('\n') + '\n';
}
return baseclass.extend({ fields: fields, defaults: defaults, parse: parse, serialize: serialize });
