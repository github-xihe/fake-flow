'use strict';
'require view';
'require form';
'require rpc';
'require ui';
'require poll';
'require fakeflow.config as config';

var get = rpc.declare({ object: 'fakeflow', method: 'get', expect: { '': {} } });
var status = rpc.declare({ object: 'fakeflow', method: 'status', expect: { '': {} } });
var validate = rpc.declare({ object: 'fakeflow', method: 'validate', params: ['config'], expect: { '': {} } });
var save = rpc.declare({ object: 'fakeflow', method: 'save',
	params: ['config', 'revision', 'enabled', 'autostart', 'apply'], expect: { '': {} } });
var action = rpc.declare({ object: 'fakeflow', method: 'action', params: ['action'], expect: { '': {} } });
function decode(value, fallback) { try { return JSON.parse(value); } catch (_) { return fallback; } }
function flag(s, tab, key, title, description) {
	var o = s.taboption(tab, form.Flag, key, title, description);
	o.rmempty = false; o.retain = true; return o;
}
function select(s, tab, key, title, choices, description) {
	var o = s.taboption(tab, form.ListValue, key, title, description);
	choices.forEach(function(c) { o.value(c[0], c[1]); }); o.rmempty = false; return o;
}
function value(s, tab, key, title, description) {
	var o = s.taboption(tab, form.Value, key, title, description), spec = config.fields[key];
	if (spec && spec[0] === 'number') o.datatype = 'and(uinteger,range(' + spec[2] + ',' + spec[3] + '))';
	o.rmempty = false; o.retain = true; return o;
}

return view.extend({
	/* Every rpc below can collide with rpcd's config lock (acquired before any work,
	 * so a 正在执行 reply means nothing happened); retry instead of nagging the user. */
	load: function() { return config.retry(get); },
	render: function(data) {
		if (!data.ok) throw new Error(data.message || '无法读取 FakeFlow 配置。');
		this.revision = data.revision;
		var model, parseError;
		try {
			model = config.parse(data.config);
			/* A JSONMap section reads its rows from the model key that matches the
			 * section name, exactly like `interface` above; without this the table
			 * comes up empty and the next save would drop the entries. */
			model.extra = model.settings.tcp_extras;
		}
		catch (e) { parseError = e.message; model = { settings: { raw: data.config } }; }
		this.rawMode = !!parseError;
		model.settings.service_enabled = data.enabled ? '1' : '0';
		model.settings.autostart = data.autostart ? '1' : '0';
		var m = this.map = new form.JSONMap(model, 'FakeFlow',
			'配置 TCP / UDP 假载荷注入。保存前会验证配置及载荷文件；“保存并应用”会重启或停止服务。');
		m.readonly = !L.hasViewPermission();
		var s = m.section(form.NamedSection, 'settings', 'settings');
		s.tab('service', '服务');
		flag(s, 'service', 'service_enabled', '启用服务');
		flag(s, 'service', 'autostart', '开机启动', '同时启用服务后，设备重启时才会自动运行。');
		if (parseError) {
			s.tab('raw', 'TOML 编辑');
			var raw = s.taboption('raw', form.TextValue, 'raw', '修复配置', parseError);
			raw.rows = 28; raw.rmempty = false;
		} else {
			s.tab('tcp', 'TCP'); s.tab('udp', 'UDP'); s.tab('injection', '注入'); s.tab('runtime', '运行参数');
			flag(s, 'tcp', 'tcp_enabled', '启用 TCP');
			select(s, 'tcp', 'tcp_directions', '触发方向', [
				['both', '主动和被动连接'], ['active', '主动连接'], ['passive', '被动连接']]);
			select(s, 'tcp', 'tcp_payload', '载荷类型', [['http', 'HTTP'], ['tls', 'TLS'], ['custom', '自定义文件']]);
			var o = value(s, 'tcp', 'tcp_hostname', '伪装域名');
			o.depends('tcp_payload', 'http'); o.depends('tcp_payload', 'tls');
			o = value(s, 'tcp', 'tcp_payload_file', '载荷文件路径', '路由器上已有的二进制文件，1–1200 字节；例如 /etc/fakehttp/payload.tls。');
			o.depends('tcp_payload', 'custom');
			/* These three are optional and always visible, so they must accept an
			 * empty value: value() defaults to rmempty = false, and a visible
			 * field with that setting fails form validation. The existing
			 * payload_file is exempt only because depends() hides it. */
			o = value(s, 'tcp', 'tcp_https_hostname', 'HTTPS 模板伪装域名',
				'可选。填了就在下面的端口上额外发送一份 TLS ClientHello，SNI 取此域名；与载荷文件只能填其一。');
			o.rmempty = true;
			o = value(s, 'tcp', 'tcp_https_payload_file', 'HTTPS 模板载荷文件',
				'可选。路由器上已有的二进制文件，1–1200 字节；与伪装域名只能填其一。');
			o.rmempty = true;
			o = value(s, 'tcp', 'tcp_https_ports', 'HTTPS 模板端口',
				'逗号分隔，最多 4 个，例如 443, 8443；留空按 443 处理。未命中的端口仍使用上面的 TCP 模板。');
			o.rmempty = true;
			select(s, 'tcp', 'tcp_tfo', 'TCP Fast Open', [['strip-syn', '首个 SYN 的 kind 34 替换为 NOP'], ['preserve', '保留 TFO']]);
			value(s, 'tcp', 'tcp_max_batches', '每次握手最多批数', '范围 1–32；握手重传的注入批次间隔至少 200 ms。');
			flag(s, 'udp', 'udp_enabled', '启用 UDP');
			select(s, 'udp', 'udp_trigger', '触发方向', [['egress', '仅出站'], ['both', '双向']],
				'双向模式只有在该流出现本地出站报文后，入站包才会触发向外发假包。');
			select(s, 'udp', 'udp_payload', '载荷类型', [['sip', 'SIP'], ['custom', '自定义文件']]);
			o = value(s, 'udp', 'udp_sip_uri', 'SIP URI', '例如 sip:user@203.0.113.1；这是载荷中的文本，不是假包的实际目的地址。');
			o.depends('udp_payload', 'sip');
			o = value(s, 'udp', 'udp_payload_file', '载荷文件路径', '路由器上已有的二进制文件，1–1200 字节。');
			o.depends('udp_payload', 'custom');
			value(s, 'udp', 'udp_initial_packets', '初期报文数', '双向共享计数，范围 1–32。支持的 UDP 分片仅首片计数，后续片原样放行。');
			value(s, 'udp', 'udp_idle_timeout_seconds', '空闲重置时间（秒）', '该流空闲超过此时间后，重新获得初期注入窗口。');
			value(s, 'injection', 'injection_ttl', 'TTL / Hop Limit');
			value(s, 'injection', 'injection_repeat', '每批副本数');
			flag(s, 'injection', 'injection_estimate_hops', '估计对端跳数');
			value(s, 'injection', 'injection_dynamic_percent', '动态跳数比例（%）', '0 表示使用固定 TTL；启用跳数估计后才有意义。');
			value(s, 'injection', 'injection_max_packets_per_second', '每接口每秒假包上限');
			value(s, 'injection', 'injection_burst', '突发额度', '不能小于每批副本数。');
			flag(s, 'injection', 'injection_allow_private', '允许私网对端', '用于内网实验；默认关闭。');
			value(s, 'runtime', 'runtime_tcp_entries', 'TCP 流表容量');
			value(s, 'runtime', 'runtime_udp_entries', 'UDP 流表容量');
			value(s, 'runtime', 'runtime_lease_seconds', '租约时间（秒）', '守护进程每 2 秒刷新。停止刷新且租约过期后停止注入。');
			var interfaces = m.section(form.TableSection, 'interface', '监听接口',
				'最多 8 个。光猫侧物理口 eth1 选 PPPoE；逻辑 pppoe-wan 选 L3。同一实例不能混用这两种路径。');
			interfaces.anonymous = true; interfaces.addremove = true; interfaces.sortable = true;
			o = interfaces.option(form.Value, 'name', '设备名称'); o.rmempty = false;
			o.validate = function(section, v) { return /^[A-Za-z0-9_.:-]{1,15}$/.test(v) || '请输入有效的设备名称。'; };
			decode(data.devices, []).forEach(function(d) { if (d.ifname) o.value(d.ifname); });
			o = interfaces.option(form.ListValue, 'mode', '模式'); o.rmempty = false; o.default = 'pppoe';
			o.value('pppoe', '物理 PPPoE'); o.value('ethernet', '普通以太网'); o.value('l3', 'L3 / 逻辑 PPP 接口');
			/* One [[tcp.extra]] table each: another port-matched template. Its port
			 * list is required, so an entry that is never reachable cannot be saved;
			 * the optional fields accept an empty value and the combination rules are
			 * reported by config.js with a per-entry message. */
			var extras = m.section(form.TableSection, 'extra', '端口匹配的 TCP 模板（[[tcp.extra]]）',
				'可选，最多 ' + config.extra_max + ' 个（与上面的 HTTPS 模板合计）。命中自己端口列表的连接改发这份假载荷，其余端口仍用主 TCP 模板；端口不能与其他模板重复。');
			extras.anonymous = true; extras.addremove = true; extras.sortable = true;
			o = extras.option(form.Value, 'hostname', '伪装域名',
				'TLS 时作为 SNI，HTTP 时作为 Host。可打印 ASCII、不含空格；与载荷文件只能填其一。');
			o.rmempty = true;
			o.validate = function(section, v) { return !v || /^[!-~]+$/.test(v) || '域名只能是可打印 ASCII，且不含空格。'; };
			o = extras.option(form.ListValue, 'payload', '生成类型', '仅有伪装域名时使用；填了载荷文件则忽略。');
			o.value('tls', 'TLS ClientHello'); o.value('http', 'HTTP 请求');
			o.default = 'tls'; o.rmempty = true;
			o = extras.option(form.Value, 'payload_file', '载荷文件路径',
				'路由器上已有的二进制文件，1–1200 字节；填了就忽略上面的伪装域名与生成类型。');
			o.rmempty = true;
			o = extras.option(form.Value, 'ports', '端口',
				'必填，逗号分隔，最多 4 个，例如 8080 或 8000, 8001；它是选择这个模板的唯一依据。');
			o.rmempty = true;
		}
		// Preview/validation also parse the JSONMap. Always read current inputs,
		// including values changed back to their initial value after a preview.
		m.children.forEach(function(section) {
			section.children.forEach(function(option) { option.forcewrite = true; });
		});
		this.statusNode = E('div', { 'class': 'cbi-section', 'id': 'fakeflow-status' });
		this.logsNode = E('pre', { 'id': 'fakeflow-logs',
			'style': 'max-height:30em;overflow:auto;white-space:pre-wrap;margin:0' });
		this.logsNote = E('p', { 'class': 'cbi-section-descr', 'id': 'fakeflow-logs-note' }, []);
		this.paintStatus(data);
		var button = function(label, handler, id) {
			return E('button', { 'class': 'cbi-button cbi-button-action', 'id': id,
				'disabled': m.readonly || null, 'click': ui.createHandlerFn(this, handler) }, [label]);
		}.bind(this);
		var toolbar = E('div', { 'class': 'cbi-section' }, [
			E('p', {}, ['以下操作使用已保存配置，不会应用表单里尚未保存的修改。']),
			button('启动', function() { return this.control('start'); }, 'ff-start'), ' ',
			button('临时停止', function() { return this.control('stop'); }, 'ff-stop'), ' ',
			button('重启', function() { return this.control('restart'); }, 'ff-restart'), ' ',
			button('校验当前表单', this.check, 'ff-validate'), ' ',
			button('预览 TOML', this.preview, 'ff-preview')
		]);
		/* Filtering happens here rather than in the daemon: the file keeps every
		 * level for post-mortem, the view defaults to hiding DEBUG (where the
		 * libbpf map and relocation detail lives). Lines written before this
		 * format existed have no level and are treated as INFO. */
		this.logLevel = this.logLevel || 'info';
		var logFilter = E('select', { 'class': 'cbi-input-select', 'id': 'ff-log-level',
			'change': ui.createHandlerFn(this, function(ev) {
				this.logLevel = ev.target.value;
				return status().then(this.paintStatus.bind(this));
			}) }, [
			E('option', { 'value': 'debug' }, ['全部（含 DEBUG）']),
			E('option', { 'value': 'info' }, ['信息及以上']),
			E('option', { 'value': 'warn' }, ['警告及以上']),
			E('option', { 'value': 'error' }, ['仅错误'])
		]);
		logFilter.value = this.logLevel;
		var logButton = E('button', { 'class': 'cbi-button cbi-button-action', 'id': 'ff-log-refresh',
			'click': ui.createHandlerFn(this, function() {
				return status().then(this.paintStatus.bind(this)).catch(this.reportError);
			}) }, ['刷新']);
		/* Its own section instead of a collapsed note: the daemon keeps its output
		 * in a file precisely so the system log stays readable, so this is where
		 * that output is meant to be read. */
		var logSection = E('div', { 'class': 'cbi-section', 'id': 'fakeflow-logs-section' }, [
			E('h3', {}, ['运行日志']),
			this.logsNote,
			E('p', {}, ['级别：', logFilter, ' ', logButton]),
			this.logsNode
		]);
		/* LuCI's poll keeps ticking in a hidden tab — it never looks at
		 * document.hidden — and every tick costs the router about ten process
		 * spawns (two fakeflow calls, two tails, three uci, ubus and jsonfilter).
		 * Skip the tick while the page is not visible and refresh at once when it
		 * comes back, so nothing shown here can go stale. */
		var visible = function() { return document.visibilityState !== 'hidden'; };
		document.addEventListener('visibilitychange', function() {
			if (visible()) return this.refreshStatus();
		}.bind(this));
		poll.add(function() {
			if (!visible()) return;
			return this.refreshStatus();
		}.bind(this), 5);
		return m.render().then(function(formNode) {
			return E('div', {}, [this.statusNode, toolbar, formNode,
				E('p', {}, ['表单保存会规范化 TOML 格式并移除注释；上次配置保存在 /etc/fakeflow.toml.luci-backup。']),
				logSection]);
		}.bind(this));
	},
	paintStatus: function(data) {
		var state = decode(data.status, {}), stats = decode(data.stats, {});
		var expanded = this.statusNode.querySelector('details[open]') !== null;
		var text = state.running ? (data.managed ? '运行中 · procd 托管' : '运行中 · 手动实例') : '已停止';
		var cards = [['fake_submit_ok', '假包提交成功'], ['tcp_synack_eligible', 'TCP 可注入握手'],
			['udp_early_seen', 'UDP 初期报文'], ['builder_failed', '假包构造失败']];
		this.statusNode.replaceChildren(E('h3', {}, [text]),
			E('p', {}, ['配置世代：' + (state.generation == null ? '—' : state.generation) + '；开机启动：' + (data.autostart ? '是' : '否')]),
			E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1em' }, cards.map(function(c) {
				return E('div', {}, [E('strong', { 'style': 'font-size:1.5em' }, [stats[c[0]] == null ? '—' : String(stats[c[0]])]), E('div', {}, [c[1]])]);
			})), E('details', { 'open': expanded ? '' : null }, [E('summary', {}, ['全部计数器']),
				E('table', { 'class': 'table' }, Object.keys(stats).map(function(k) {
					return E('tr', { 'class': 'tr' }, [E('td', { 'class': 'td' }, [k]), E('td', { 'class': 'td' }, [String(stats[k])])]);
				}))]));
		/* Level filtering: the daemon stamps every line, the file keeps all levels
		 * for post-mortem, and this view decides what to display. */
		var ranks = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3 };
		var limit = ranks[String(this.logLevel || 'info').toUpperCase()];
		if (typeof limit !== 'number') limit = ranks.INFO;
		var all = String(data.logs || '').split('\n').filter(function(l) { return l !== ''; });
		var shown = all.filter(function(line) {
			var m = line.match(/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+([A-Z]+)\s/);
			var rank = m && typeof ranks[m[1]] === 'number' ? ranks[m[1]] : ranks.INFO;
			return rank <= limit;
		});
		this.logsNode.textContent = shown.length ? shown.join('\n') : '暂无日志。';
		this.logsNote.textContent = '来自 /var/log/fakeflow.log（每 5 秒自动刷新；最多显示最近 400 行）。共 '
			+ all.length + ' 行，显示 ' + shown.length + ' 行'
			+ (all.length > shown.length ? '，已按级别隐藏 ' + (all.length - shown.length) + ' 行。' : '。');
	},
	container: function() { return this.map.data.sections('json', 'interface'); },
	/* The array of tables lives in its own JSONMap section, like the
	 * interfaces, and serialize() expects it on the settings object. */
	settingsWithExtras: function() {
		var settings = this.map.data.get('json', 'settings');
		if (!this.rawMode) settings.tcp_extras = this.map.data.sections('json', 'extra');
		return settings;
	},
	candidate: function() {
		this.map.checkDepends();
		return this.map.parse().then(function() {
			var settings = this.settingsWithExtras();
			return { config: this.rawMode ? settings.raw : config.serialize(settings, this.container()),
				enabled: settings.service_enabled === '1', autostart: settings.autostart === '1' };
		}.bind(this));
	},
	result: function(result) {
		if (result.saved && result.revision) this.revision = result.revision;
		if (!result.ok) throw new Error(result.message || '操作失败。');
		ui.addNotification(null, E('p', {}, [result.message]), 'info');
		return status().then(this.paintStatus.bind(this));
	},
	reportError: function(e) { ui.addNotification(null, E('p', {}, [e.message]), 'danger'); },
	/* One status refresh, shared by the poll, the visibility listener and the
	 * button handlers, so they all paint and fail the same way. */
	refreshStatus: function() {
		return status().then(this.paintStatus.bind(this)).catch(this.statusFailed.bind(this));
	},
	statusFailed: function() {
		this.statusNode.replaceChildren(E('p', {}, ['暂时无法获取状态，等待重试……']));
	},
	control: function(name) {
		return config.retry(function() { return action(name); }).then(this.result.bind(this)).catch(this.reportError);
	},
	check: function() {
		return this.candidate().then(function(c) {
			return config.retry(function() { return validate(c.config); });
		}).then(this.result.bind(this)).catch(this.reportError);
	},
	preview: function() {
		return this.candidate().then(function(c) {
			ui.showModal('TOML 预览', [E('pre', { 'style': 'max-height:60vh;overflow:auto' }, [c.config]),
				E('div', { 'class': 'right' }, [E('button', { 'class': 'cbi-button', 'click': ui.hideModal }, ['关闭'])])]);
		}).catch(this.reportError);
	},
	persist: function(apply) {
		return this.candidate().then(function(c) {
			return config.retry(function() {
				return save(c.config, this.revision, c.enabled, c.autostart, apply);
			}.bind(this));
		}.bind(this)).then(this.result.bind(this)).catch(this.reportError);
	},
	handleSave: function() { return this.persist(false); },
	handleSaveApply: function() { return this.persist(true); },
	handleReset: function() { window.location.reload(); }
});
