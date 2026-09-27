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
			select(s, 'tcp', 'tcp_directions', '连接方向', [
				['both', '主动和被动连接'], ['active', '主动连接'], ['passive', '被动连接']]);
			/* TCP payload rules. The model is a list, so it is edited as a table: the
			 * row order is the order the daemon rotates through, a disabled row stays
			 * in the file but is never published, and each connection is pinned to one
			 * rule so it never mixes an HTTP Host with a TLS SNI. The payload column
			 * holds a bare host name for HTTP/TLS and an absolute path for
			 * 自定义文件; LuCI cannot express that condition, so config.js checks it on
			 * save and names the offending row. */
			/* A TableSection is what the interface table above already proves works in
			 * this LuCI build; a GridSection here left the whole view unrendered. Row
			 * order is the file order, which is the rotation order. */
			var tbl = m.section(form.TableSection, 'rule', 'TCP 载荷规则',
				'每条连接在建立时固定使用其中一条规则，连接之间按这里的顺序轮换。');
			tbl.addremove = true; tbl.anonymous = true;
			var to = tbl.option(form.Flag, 'enabled', '启用');
			to.default = '1'; to.rmempty = false;
			to = tbl.option(form.ListValue, 'type', '类型');
			to.value('http', 'HTTP'); to.value('tls', 'TLS'); to.value('custom', '自定义文件');
			to.rmempty = false;
			to = tbl.option(form.Value, 'payload', '载荷',
				'HTTP / TLS 填裸域名，例如 speed.gx.chinamobile.com —— 不要写 http://、端口或路径；'
				+ '自定义文件填路由器上已有的文件绝对路径，例如 /etc/fakehttp/payload.tls。'
				+ '生成 HTTP 时域名进 Host 头，生成 TLS 时进 SNI（握手里的服务器名）。');
			to.rmempty = false;
			tbl.option(form.Value, 'comment', '备注').rmempty = true;
			select(s, 'tcp', 'tcp_tfo', 'TCP Fast Open', [['strip-syn', '把首个 SYN 里的 TFO 选项替换为空操作（NOP）'], ['preserve', '保留 TFO']]);
			value(s, 'tcp', 'tcp_max_batches', '每次握手的注入批数上限', '范围 1–32；握手重传的注入批次间隔至少 200 ms。');
			flag(s, 'udp', 'udp_enabled', '启用 UDP');
			select(s, 'udp', 'udp_trigger', '入站触发', [['egress', '仅出站'], ['both', '双向']],
				'双向模式只有在该流出现本地出站报文后，入站包才会触发向外发假包。');
			select(s, 'udp', 'udp_payload', '载荷类型', [['sip', 'SIP'], ['custom', '自定义文件']]);
			/* 同上：hidden 的条件字段不能是必填，否则 depends 隐藏后残留的无效标记会在
			 * 切换页签时变成「N 个无效字段」提示；规则由 config.js 兜底。 */
			o = value(s, 'udp', 'udp_sip_uri', 'SIP URI', '例如 sip:user@203.0.113.1；这是载荷中的文本，不是假包的实际目的地址。');
			o.rmempty = true;
			o.depends('udp_payload', 'sip');
			o = value(s, 'udp', 'udp_payload_file', '载荷文件路径', '路由器上已有的二进制文件，1–1200 字节。');
			o.rmempty = true;
			o.depends('udp_payload', 'custom');
			value(s, 'udp', 'udp_initial_packets', '初期报文数', '双向共享计数，范围 1–32。支持的 UDP 分片仅首片计数，后续片原样放行。');
			value(s, 'udp', 'udp_idle_timeout_seconds', '空闲重置时间（秒）', '该流空闲超过此时间后，重新获得初期注入窗口。');
			value(s, 'injection', 'injection_ttl', 'TTL / Hop Limit');
			value(s, 'injection', 'injection_repeat', '每批副本数');
			flag(s, 'injection', 'injection_estimate_hops', '估计对端跳数');
			value(s, 'injection', 'injection_dynamic_percent', '动态跳数比例（%）',
				'0 = 固定使用上面的 TTL。非 0 时按「估算跳数 × 比例」抬高 TTL（只抬高、不会降低）；一旦 TTL 达到或超过估算跳数就不注入（对端太近）。注意跳数估计与这个值无关：即使填 0，它仍负责判断「对端是否太近」。');
			value(s, 'injection', 'injection_max_packets_per_second', '每接口每秒假包上限');
			value(s, 'injection', 'injection_burst', '突发容量', '令牌桶容量，不能小于每批副本数。');
			flag(s, 'injection', 'injection_allow_private', '允许向私网对端注入', '用于内网实验；默认关闭。');
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
		var text = state.running ? (data.managed ? '运行中 · 由系统托管' : '运行中 · 手动启动') : '已停止';
		var cards = [['fake_submit_ok', '假包已注入'], ['tcp_synack_eligible', '可注入 TCP 握手'],
			['udp_early_seen', 'UDP 初期窗口报文'], ['builder_failed', '假包构造失败']];
		this.statusNode.replaceChildren(E('h3', {}, [text]),
			E('p', { 'title': '守护进程每次成功应用配置后递增，从本次启动起算。' },
				['配置版本：' + (state.generation == null ? '—' : state.generation) + '；开机启动：' + (data.autostart ? '是' : '否')]),
			E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1em' }, cards.map(function(c) {
				return E('div', {}, [E('strong', { 'style': 'font-size:1.5em' }, [stats[c[0]] == null ? '—' : String(stats[c[0]])]), E('div', {}, [c[1]])]);
			})), E('p', { 'class': 'cbi-section-descr' },
				['「假包已注入」表示假包已构造并送出，不代表对端一定收到；「可注入 TCP 握手」表示该握手满足注入条件，'
					+ '是否真的注入还受速率与租约限制。']),
			E('details', { 'open': expanded ? '' : null }, [E('summary', {}, ['全部计数器']),
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
		this.logsNote.textContent = '来自 /var/log/fakeflow.log（页面可见时每 5 秒刷新，切回前台立即刷新一次；最多显示最近 400 行）。共 '
			+ all.length + ' 行，显示 ' + shown.length + ' 行'
			+ (all.length > shown.length ? '，已按级别隐藏 ' + (all.length - shown.length) + ' 行。' : '。');
	},
	candidate: function() {
		this.map.checkDepends();
		return this.map.parse().then(function() {
			var settings = this.map.data.get('json', 'settings');
			return { config: this.rawMode ? settings.raw : config.serialize(settings, this.map.data.sections('json', 'interface')),
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
