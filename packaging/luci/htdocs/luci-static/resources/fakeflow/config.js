'use strict';
'require baseclass';

// The supported TOML subset matches ebpf/user/config.c. Never evaluate input.
var fields = {
	tcp_enabled: ['bool', true], tcp_directions: ['directions', 'both'],
	tcp_payload: ['enum', 'http', ['http', 'tls', 'custom']],
	tcp_hostname: ['string', 'www.example.com'], tcp_payload_file: ['string', ''],
	tcp_https_hostname: ['string', ''], tcp_https_payload_file: ['string', ''],
	tcp_https_ports: ['ports', ''],
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
// One [[tcp.extra]] entry: another port-matched TCP template. `payload` is the kind
// generated from `hostname` (tls = ClientHello with SNI, http = GET with Host), and
// `payload_file` wins over it, exactly as the parser treats an explicit file.
var extra_fields = {
	hostname: ['string', ''], payload: ['enum', 'tls', ['tls', 'http']],
	payload_file: ['string', ''], ports: ['ports', '']
};
// FF_TCP_EXTRA_MAX: port-matched templates in total, https_* included.
var extra_max = 3;
function defaults() {
	var values = { tcp_extras: [] };
	Object.keys(fields).forEach(function(k) {
		values[k] = fields[k][0] === 'bool' ? (fields[k][1] ? '1' : '0') : String(fields[k][1]);
	});
	return values;
}
function quote(value, field) {
	var where = field ? field + '：' : '';
	/* Name the field: a bare "text must not contain quotes" leaves the user
	 * hunting 27 options, and a non-string value (LuCI hands over null for a field
	 * the form left empty) produced exactly the same unhelpful message. */
	if (typeof value !== 'string')
		throw new Error(where + '需要一个文本值，实际收到' + (value === null ? '空值' : typeof value) + '。');
	if (/["\\\x00-\x1f]/.test(value))
		throw new Error(where + '文本不能包含双引号、反斜杠或换行。');
	return '"' + value + '"';
}
function extras_of(settings) {
	return Array.isArray(settings.tcp_extras) ? settings.tcp_extras : [];
}
/* The daemon answers these two while its config lock is held. rpcd acquires the
 * lock before doing any work (get, validate, save and action all do), so such a
 * reply means nothing happened and the identical request can simply be repeated.
 * Applying holds the lock across the whole service restart — long enough for the
 * page's own 5 s status poll or an impatient second click to collide with it. */
function transient(message) {
	var text = message === undefined || message === null ? '' : String(message);
	return text.indexOf('正在执行') >= 0 || text.indexOf('锁繁忙') >= 0;
}
function retry(fn, attempts, wait) {
	attempts = attempts === undefined ? 4 : attempts;
	wait = wait === undefined ? 1000 : wait;
	return fn().then(function(result) {
		if (attempts <= 1 || !result || result.ok !== false || !transient(result.message))
			return result;
		return new Promise(function(resolve) { setTimeout(resolve, wait); }).then(function() {
			return retry(fn, attempts - 1, wait * 2);
		});
	});
}
// '443, 8443' -> [443, 8443]. The port list is the only thing that selects a
// template, so an empty list is refused instead of quietly matching nothing.
function port_list(value, what) {
	var list = String(value === undefined || value === null ? '' : value)
		.split(',').map(function(s) { return s.trim(); }).filter(function(s) { return s.length; });
	if (!list.length) throw new Error(what + '：端口列表不能为空。');
	if (list.length > 4) throw new Error(what + '：端口列表最多 4 个端口。');
	if (list.some(function(s) { return !/^\d+$/.test(s) || +s < 1 || +s > 65535; }))
		throw new Error(what + '：端口值超出范围。');
	var nums = list.map(Number);
	if (new Set(nums).size !== nums.length) throw new Error(what + '：端口重复。');
	return nums;
}
function check_extras(settings) {
	var list = extras_of(settings), owner = {};
	var used = (settings.tcp_https_hostname || settings.tcp_https_payload_file) ? 1 : 0;
	if (used + list.length > extra_max)
		throw new Error('端口匹配的 TCP 模板最多 ' + extra_max + ' 个（https_* 与 [[tcp.extra]] 合计）。');
	if (used && settings.tcp_https_ports)
		port_list(settings.tcp_https_ports, 'HTTPS 模板').forEach(function(p) { owner[p] = 'HTTPS 模板'; });
	else if (used)
		/* The parser defaults the port-matched template to 443 when the list is
		 * empty, so an entry claiming 443 collides with it. */
		owner[443] = 'HTTPS 模板';
	list.forEach(function(entry, index) {
		var what = '第 ' + (index + 1) + ' 个 [[tcp.extra]]';
		if (entry.hostname && entry.payload_file)
			throw new Error(what + '：伪装域名与载荷文件只能填其一。');
		if (!entry.hostname && !entry.payload_file)
			throw new Error(what + '：需要伪装域名或载荷文件。');
		/* A freshly added row may not carry the payload key at all: that means the
		 * documented default, not an invalid choice. */
		var kind = entry.payload === undefined || entry.payload === null || entry.payload === ''
			? 'tls' : entry.payload;
		if (['tls', 'http'].indexOf(kind) < 0)
			throw new Error(what + '：生成类型无效。');
		// The datapath takes the first slot whose list contains the port, so a port
		// claimed twice would leave one of the templates unreachable.
		port_list(entry.ports, what).forEach(function(p) {
			if (owner[p]) throw new Error('端口 ' + p + ' 被 ' + owner[p] + ' 与 ' + what + ' 同时占用。');
			owner[p] = what;
		});
	});
	return list;
}
function parse(text) {
	var settings = defaults(), interfaces = [], extras = [], section = '', seen = {}, sections = {}, version = false;
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
		if (line === '[[tcp.extra]]') {
			if (extras.length >= extra_max) fail();
			section = 'tcp.extra';
			extras.push({ hostname: '', payload: 'tls', payload_file: '', ports: '' });
			return;
		}
		if (/^\[(tcp|udp|injection|runtime)\]$/.test(line)) {
			section = line.slice(1, -1);
			if (sections[section]) fail();
			sections[section] = true; return;
		}
		var match = line.match(/^([a-z_]+)\s*=\s*(.+)$/);
		if (!match) fail();
		var key = match[1], value = match[2];
		var repeat = section === 'interfaces' ? interfaces.length : section === 'tcp.extra' ? extras.length : 0;
		var id = section + '.' + repeat + '.' + key;
		if (seen[id]) fail();
		seen[id] = true;
		if (!section && key === 'version' && value === '1') { version = true; return; }
		var spec = section === 'interfaces' && (key === 'name' || key === 'mode') ? ['string'] :
			section === 'tcp.extra' ? extra_fields[key] : fields[section + '_' + key];
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
		} else if (spec[0] === 'ports') {
			var ports;
			try { ports = JSON.parse(value); } catch (_) { fail(); }
			if (!Array.isArray(ports) || !ports.length || ports.length > 4 ||
				ports.some(function(v) { return !Number.isInteger(v) || v < 1 || v > 65535; }) ||
				new Set(ports).size !== ports.length) fail();
			parsed = ports.join(', ');
		} else {
			if (!/^"[^"\\\x00-\x1f]*"$/.test(value)) fail();
			parsed = value.slice(1, -1);
			if (spec[0] === 'enum' && spec[2].indexOf(parsed) < 0) fail();
		}
		if (section === 'interfaces') interfaces[interfaces.length - 1][key] = parsed;
		else if (section === 'tcp.extra') extras[extras.length - 1][key] = parsed;
		else settings[section + '_' + key] = parsed;
	});
	if (!version || !interfaces.length) throw new Error('需要 version = 1 和至少一个接口。');
	settings.tcp_extras = extras;
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
	if (settings.tcp_https_hostname && settings.tcp_https_payload_file)
		throw new Error('HTTPS 模板只能填伪装域名或载荷文件其中之一。');
	var extras = check_extras(settings);
	['tcp', 'udp', 'injection', 'runtime'].forEach(function(section) {
		lines.push('', '[' + section + ']');
		Object.keys(fields).forEach(function(id) {
			if (id.indexOf(section + '_') !== 0) return;
			var key = id.slice(section.length + 1), spec = fields[id], value = settings[id];
			/* Complain in TOML terms (`tcp.https_hostname`), which is what the user
			 * sees in the file and in the TOML preview. */
			var label = section + '.' + key;
			if ((section === 'tcp' || section === 'udp') &&
				((key === 'payload_file' && settings[section + '_payload'] !== 'custom') ||
				((key === 'hostname' || key === 'sip_uri') && settings[section + '_payload'] === 'custom'))) return;
			/* The port-matched template exists only when one of its payload
			 * sources is set, so its keys are omitted otherwise. */
			if (section === 'tcp' && key.indexOf('https_') === 0 &&
				!settings.tcp_https_hostname && !settings.tcp_https_payload_file) return;
			if (spec[0] === 'bool') {
				if (value !== '0' && value !== '1') throw new Error(label + ': 开关值无效。');
				value = value === '1' ? 'true' : 'false';
			} else if (spec[0] === 'number') {
				if (!/^\d+$/.test(String(value))) throw new Error(label + ': 需要一个整数。');
				if (+value < spec[2] || +value > spec[3])
					throw new Error(label + ': 数值超出范围（' + spec[2] + '–' + spec[3] + '）。');
				value = String(+value);
			} else if (spec[0] === 'directions') {
				if (['active', 'passive', 'both'].indexOf(value) < 0) throw new Error(label + ': TCP 方向无效。');
				value = value === 'both' ? '["active", "passive"]' : '[' + quote(value, label) + ']';
			} else if (spec[0] === 'ports') {
				if (!String(value === undefined || value === null ? '' : value).trim()) return;	/* omitted: 443 */
				value = '[' + port_list(value, label).join(', ') + ']';
			} else {
				if (spec[0] === 'enum' && spec[2].indexOf(value) < 0) throw new Error(label + ': 选项无效。');
				/* LuCI hands over null/undefined for a field the form left empty.
				 * Treat that as "not set": a field whose declared default is not empty
				 * is still required, but an optional one must not fail the whole form
				 * (which is what produced a bare "cannot contain quotes" notice). */
				if (value === undefined || value === null) value = '';
				/* An empty optional field means "not set": omit the key instead of
				 * writing `key = ""`. That is what the form hands over for a field the
				 * user never filled — e.g. https_payload_file while https_hostname is
				 * set — and writing it empty would also be noise in the file. */
				if (!value) {
					if (spec[1] !== '') throw new Error(label + ': 不能为空。');
					return;
				}
				value = quote(value, label);
			}
			lines.push(key + ' = ' + value);
		});
		/* The array of tables belongs to [tcp], so it is emitted before the next
		 * section header: a key after [[tcp.extra]] would land in the last entry. */
		if (section !== 'tcp') return;
		extras.forEach(function(entry) {
			lines.push('', '[[tcp.extra]]');
			if (entry.payload_file) lines.push('payload_file = ' + quote(entry.payload_file, '[[tcp.extra]] payload_file'));
			else {
				var host = entry.hostname === undefined || entry.hostname === null ? '' : entry.hostname;
				lines.push('hostname = ' + quote(host, '[[tcp.extra]] hostname'));
				lines.push('payload = ' + quote(entry.payload === 'http' ? 'http' : 'tls', '[[tcp.extra]] payload'));
			}
			lines.push('ports = [' + port_list(entry.ports, '[[tcp.extra]]').join(', ') + ']');
		});
	});
	return lines.join('\n') + '\n';
}
return baseclass.extend({ fields: fields, extra_fields: extra_fields, extra_max: extra_max,
	transient: transient, retry: retry,
	defaults: defaults, parse: parse, serialize: serialize });
