'use strict';
'require baseclass';

// The supported TOML subset matches ebpf/user/config.c. Never evaluate input.
var fields = {
	tcp_enabled: ['bool', true], tcp_directions: ['directions', 'both'],
	/* Retired single-template keys. They are still read (an existing router
	 * configuration keeps loading and is rewritten as rules on the next save) but
	 * never written back; the rule table below is the model now. */
	tcp_payload: ['enum', 'http', ['http', 'tls', 'custom'], 'retired'],
	tcp_hostname: ['string', 'www.example.com', 'retired'], tcp_payload_file: ['string', '', 'retired'],
	tcp_https_hostname: ['string', '', 'retired'], tcp_https_payload_file: ['string', '', 'retired'],
	tcp_https_ports: ['ports', '', 'retired'],
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
// '443, 8443' -> [443, 8443]. The port list is the only thing that selects the
// second TCP template, so an empty list is refused instead of quietly matching
// nothing.
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
/* One TCP payload rule. `payload` is a host name for type http/tls and a file
 * path for type custom, which is the daemon's own reading of the field. */
function new_rule() { return { enabled: '1', type: 'http', payload: '', comment: '' }; }
function parse(text) {
	var settings = defaults(), interfaces = [], rules = [], section = '', seen = {}, sections = {}, version = false;
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
		if (line === '[[tcp.rule]]') {
			section = 'tcp.rule'; rules.push(new_rule()); return;
		}
		if (/^\[(tcp|udp|injection|runtime)\]$/.test(line)) {
			section = line.slice(1, -1);
			if (sections[section]) fail();
			sections[section] = true; return;
		}
		var match = line.match(/^([a-z_]+)\s*=\s*(.+)$/);
		if (!match) fail();
		var key = match[1], value = match[2];
		var repeat = section === 'interfaces' ? interfaces.length : section === 'tcp.rule' ? rules.length : 0;
		var id = section + '.' + repeat + '.' + key;
		if (seen[id]) fail();
		seen[id] = true;
		if (!section && key === 'version' && value === '1') { version = true; return; }
		var spec = section === 'interfaces' && (key === 'name' || key === 'mode') ? ['string'] :
			section === 'tcp.rule' && key === 'enabled' ? ['bool'] :
			section === 'tcp.rule' && key === 'type' ? ['enum', 'http', ['http', 'tls', 'custom']] :
			section === 'tcp.rule' && (key === 'payload' || key === 'comment') ? ['string'] :
			fields[section + '_' + key];
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
		else if (section === 'tcp.rule') rules[rules.length - 1][key] = parsed;
		else settings[section + '_' + key] = parsed;
	});
	if (!version || !interfaces.length) throw new Error('需要 version = 1 和至少一个接口。');
		/* A configuration written before the rule table existed carries the payload in
	 * the flat keys; turn it into rules so the form shows what the daemon runs. */
	if (!rules.length) {
		var legacy = new_rule();
		legacy.type = settings.tcp_payload === 'custom' ? 'custom' : settings.tcp_payload === 'tls' ? 'tls' : 'http';
		legacy.payload = legacy.type === 'custom' ? settings.tcp_payload_file : settings.tcp_hostname;
		rules.push(legacy);
		if (settings.tcp_https_hostname || settings.tcp_https_payload_file) {
			var second = new_rule();
			second.type = settings.tcp_https_payload_file ? 'custom' : 'tls';
			second.payload = settings.tcp_https_payload_file || settings.tcp_https_hostname;
			rules.push(second);
		}
	}
	// Validate names and combinations before allowing a form rewrite.
	serialize(settings, interfaces, rules);
	return { settings: settings, interface: interfaces, rule: rules };
}
/* A bare host name: no scheme, no port, no path. The daemon embeds this string
 * verbatim in the Host header or the TLS SNI, so "http://host/" or "host:443"
 * would read as forged traffic rather than as a disguise. */
function rule_host(value, what) {
	if (!value) throw new Error(what + '：载荷不能为空。');
	if (/[\/: ]/.test(value)) throw new Error(what + '：域名要写成裸域名（不要协议、端口或路径）。');
	return quote(value, what);
}
function rule_list(rules) {
	if (!rules || !rules.length) throw new Error('TCP 规则表至少需要一条规则。');
	if (rules.length > 3) throw new Error('TCP 规则表最多 3 条规则。');
	var lines = [], enabled = 0, index = 0;
	rules.forEach(function(r) {
		index++;
		var where = 'tcp.rule #' + index;
		var type = r.type === 'tls' ? 'tls' : r.type === 'custom' ? 'custom' : 'http';
		var on = r.enabled === '1' || r.enabled === true || r.enabled === 1;
		if (on) enabled++;
		if (!String(r.payload === undefined || r.payload === null ? '' : r.payload).length)
			throw new Error(where + '：' + (type === 'custom' ? '载荷文件' : '域名') + '不能为空。');
		if (type === 'custom' && String(r.payload)[0] !== '/')
			throw new Error(where + '：载荷文件要写绝对路径，例如 /etc/fakehttp/payload.tls。');
		var value = type === 'custom'
			? '\"' + String(r.payload) + '\"'
			: rule_host(String(r.payload), where);
		lines.push('', '[[tcp.rule]]', 'type = \"' + type + '\"', 'payload = ' + value,
			'enabled = ' + (on ? 'true' : 'false'));
		if (r.comment) lines.push('comment = ' + quote(String(r.comment), where));
	});
	if (!enabled) throw new Error('TCP 规则表至少要有一条启用的规则。');
	return lines;
}
function serialize(settings, interfaces, rules) {
	/* An empty rule table would produce a configuration the daemon rejects, so it is
	 * refused here rather than written out and reported by the device. */
	if (!rules || !rules.length) throw new Error('TCP 规则表至少需要一条规则。');
	/* Older callers (and a form that somehow carries no rule rows) still pass two
	 * arguments; derive the rules from the retired flat keys so the output is a valid
	 * rule table either way. */
	if (!rules || !rules.length) {
		var derived = new_rule();
		derived.type = settings.tcp_payload === 'custom' ? 'custom' : settings.tcp_payload === 'tls' ? 'tls' : 'http';
		derived.payload = derived.type === 'custom' ? settings.tcp_payload_file : settings.tcp_hostname;
		rules = [derived];
		if (settings.tcp_https_hostname || settings.tcp_https_payload_file) {
			var more = new_rule();
			more.type = settings.tcp_https_payload_file ? 'custom' : 'tls';
			more.payload = settings.tcp_https_payload_file || settings.tcp_https_hostname;
			rules.push(more);
		}
	}
	if (!interfaces.length || interfaces.length > 8) throw new Error('需要配置 1–8 个接口。');
	var names = Object.create(null), modes = {}, lines = ['version = 1'];
	interfaces.forEach(function(d) {
		if (!/^[A-Za-z0-9_.:-]{1,15}$/.test(d.name) || names[d.name]) throw new Error('接口名称无效或重复。');
		if (['ethernet', 'pppoe', 'l3'].indexOf(d.mode) < 0) throw new Error('接口模式无效。');
		names[d.name] = true; modes[d.mode] = true;
		lines.push('', '[[interfaces]]', 'name = ' + quote(d.name), 'mode = ' + quote(d.mode));
	});
	if (modes.pppoe && modes.l3) throw new Error('同一实例不能同时使用物理 PPPoE 和 L3 模式。');
	if (+settings.injection_burst < +settings.injection_repeat) throw new Error('突发容量不能小于每批副本数。');
	if (settings.tcp_https_hostname && settings.tcp_https_payload_file)
		throw new Error('第二个 TCP 模板只能填伪装域名或载荷文件其中之一。');
	/* 「载荷类型选了自定义文件就必须给路径」这条规则是有条件的，表单层表达不了
	 * （见 view/fakeflow.js 里 rmempty 的说明），所以在这里兜底，并按 TOML 路径报错。 */
	if (settings.tcp_payload === 'custom' && !settings.tcp_payload_file)
		throw new Error('tcp.payload_file: 载荷类型选择「自定义文件」时必须填写载荷文件路径。');
	if (settings.udp_payload === 'custom' && !settings.udp_payload_file)
		throw new Error('udp.payload_file: 载荷类型选择「自定义文件」时必须填写载荷文件路径。');
	['tcp', 'udp', 'injection', 'runtime'].forEach(function(section) {
		lines.push('', '[' + section + ']');
		/* The rule table replaces the retired flat TCP payload keys, so those are
		 * parsed but never written again; that is also what migrates a router's
		 * existing configuration on the next save. */
		var table = rules && rules.length ? rules : [];
		Object.keys(fields).forEach(function(id) {
			if (id.indexOf(section + '_') !== 0) return;
			if (fields[id][fields[id].length - 1] === 'retired') return;   /* enum specs carry choices at [2] */
			var key = id.slice(section.length + 1), spec = fields[id], value = settings[id];
			/* Complain in TOML terms (`tcp.https_hostname`), which is what the user
			 * sees in the file and in the TOML preview. */
			var label = section + '.' + key;
			if ((section === 'tcp' || section === 'udp') &&
				((key === 'payload_file' && settings[section + '_payload'] !== 'custom') ||
				((key === 'hostname' || key === 'sip_uri') && settings[section + '_payload'] === 'custom'))) return;
			/* The second TCP template exists only when one of its payload sources
			 * is set, so its keys are omitted otherwise. */
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
		if (section === 'tcp' && table.length) lines = lines.concat(rule_list(table));
	});
	return lines.join('\n') + '\n';
}
return baseclass.extend({ fields: fields, transient: transient, retry: retry, new_rule: new_rule,
	defaults: defaults, parse: parse, serialize: serialize });
