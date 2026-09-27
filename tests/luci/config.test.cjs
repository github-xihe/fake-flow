// Test the actual LuCI module without a browser or a router.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync('packaging/luci/htdocs/luci-static/resources/fakeflow/config.js', 'utf8');
const config = new Function('baseclass', source)({ extend: x => x });
const original = fs.readFileSync('config/fakeflow.toml', 'utf8');
const model = config.parse(original);
const roundtrip = m => config.parse(config.serialize(m.settings, m.interface));
assert.deepEqual(roundtrip(model), model);
assert.equal(model.settings.udp_initial_packets, '5');
for (const direction of ['active', 'passive', 'both']) {
  const m = structuredClone(model);
  m.settings.tcp_directions = direction;
  assert.deepEqual(roundtrip(m), m);
}
const custom = structuredClone(model);
custom.settings.tcp_payload = 'custom';
custom.settings.tcp_payload_file = '/etc/fakehttp/payload.tls';
custom.settings.udp_payload = 'custom';
custom.settings.udp_payload_file = '/tmp/payload#not-comment.bin';
const serialized = config.serialize(custom.settings, custom.interface);
assert(!serialized.includes('hostname ='));
assert(!serialized.includes('sip_uri ='));
assert.equal(config.parse(serialized).settings.tcp_payload_file, '/etc/fakehttp/payload.tls');
assert.equal(config.parse(serialized).settings.udp_payload_file, '/tmp/payload#not-comment.bin');
assert.deepEqual(config.parse('# comment\n' + original.replace(/\n/g, ' # comment\r\n')), model);
for (const bad of [
  original + '\n[unknown]\nx = 1', original.replace('version = 1', 'version = 2'),
  original.replace('[tcp]', '[tcp]\nenabled = true'), original + '\n[tcp]',
  original.replace('initial_packets = 5', 'initial_packets = 33'),
  original.replace('"active", "passive"', '"active", "active"'),
  original.replace('enabled = true', 'enabled = 1'),
  original.replace('hostname = "www.example.com"', 'hostname = "bad\\\\name"')
]) assert.throws(() => config.parse(bad));
for (const [key, value] of [['injection_ttl','0'], ['runtime_lease_seconds','3'],
  ['injection_burst','1'], ['tcp_hostname','x"\nenabled = false'], ['udp_trigger','ingress']]) {
  assert.throws(() => config.serialize({ ...model.settings, [key]: value }, model.interface));
}
assert.throws(() => config.serialize(model.settings, []));
assert.throws(() => config.serialize(model.settings, [model.interface[0], model.interface[0]]));
assert.throws(() => config.serialize(model.settings, [{ name:'eth0',mode:'pppoe' },{ name:'pppoe-wan',mode:'l3' }]));
const eight = Array.from({ length:8 }, (_,i) => ({ name:'eth'+i,mode:'ethernet' }));
assert.equal(config.parse(config.serialize(model.settings, eight)).interface.length, 8);
assert.throws(() => config.serialize(model.settings, [...eight,{ name:'eth8',mode:'ethernet' }]));
// Port-matched second TCP template: roundtrip, default port list and rejection.
const https = structuredClone(model);
https.settings.tcp_https_hostname = 'tls.example';
let text = config.serialize(https.settings, https.interface);
assert(text.includes('https_hostname = "tls.example"'));
assert(!text.includes('https_ports ='), 'an empty port list must be omitted so the parser default applies');
assert.equal(config.parse(text).settings.tcp_https_hostname, 'tls.example');
assert.deepEqual(roundtrip(https), https);
https.settings.tcp_https_ports = '443, 8443';
text = config.serialize(https.settings, https.interface);
assert(text.includes('https_ports = [443, 8443]'));
assert.equal(config.parse(text).settings.tcp_https_ports, '443, 8443');
assert.deepEqual(roundtrip(https), https);
for (const ports of ['0', '65536', '443, 443', '1,2,3,4,5', '443, x'])
  assert.throws(() => config.serialize({ ...https.settings, tcp_https_ports: ports }, https.interface));
assert.throws(() => config.serialize({ ...https.settings, tcp_https_payload_file: '/tmp/x' }, https.interface));
const ht='hostname = "www.example.com"';
for (const key of ['https_ports = []', 'https_ports = [443, 443]', 'https_ports = [0]', 'https_ports = [443,]'])
  assert.throws(() => config.parse(original.replace(ht, ht + '\n' + key)));
// The second template is omitted entirely when no payload source is configured.
assert(!config.serialize(model.settings, model.interface).includes('https_'));
// A field whose default is empty and which is always visible must accept an
// empty value: value() sets rmempty = false, and LuCI refuses to parse a visible
// empty field. That failure only surfaces in the browser test, so check it here.
const viewSource = fs.readFileSync('packaging/luci/htdocs/luci-static/resources/view/fakeflow.js', 'utf8');
for (const [key, spec] of Object.entries(config.fields)) {
  if (spec[1] !== '') continue;
  const call = new RegExp("value\\(s, '[a-z]+', '" + key + "'");
  const idx = viewSource.search(call);
  if (idx < 0) continue;
  const snippet = viewSource.slice(idx, idx + 400);
  assert(snippet.includes('rmempty = true') || snippet.includes('.depends('),
    key + ' 默认值为空且常显，必须设 rmempty = true 或加 depends()');
}
// LuCI hands over null/undefined for a form field the user left empty. That must
// not fail the whole form, and when something *is* wrong the message has to name
// the field.
const blank = { ...model.settings, tcp_payload_file: null, tcp_https_hostname: null,
  tcp_https_payload_file: null, udp_payload_file: null };
assert.equal(config.serialize(blank, model.interface), config.serialize(model.settings, model.interface),
  'empty optional fields must serialize exactly as if they were unset');
for (const [settings, expected] of [
  [{ ...model.settings, tcp_hostname: 'x"\ny' }, /tcp\.hostname.*不能包含双引号/],
  [{ ...model.settings, tcp_hostname: null }, /tcp\.hostname.*不能为空/],
  [{ ...model.settings, udp_initial_packets: null }, /udp\.initial_packets.*需要一个整数/]
]) assert.throws(() => config.serialize(settings, model.interface), expected);
// The reported failure: a config that turns on the https_* template leaves the
// HTTPS payload_file empty in the form, LuCI hands that over as null/undefined,
// and the serializer used to die with a message that named no field.
const httpsForm = { ...model.settings, tcp_https_hostname: 'tls.example', tcp_https_payload_file: null };
const httpsText = config.serialize(httpsForm, model.interface);
assert(httpsText.includes('https_hostname = "tls.example"'), httpsText);
assert(!httpsText.includes('https_payload_file'),
  'an empty optional field is omitted, not written as key = ""');
assert.deepEqual(config.parse(httpsText).settings.tcp_https_hostname, 'tls.example');
for (const off of [null, undefined, 0, ''])
  assert(!config.serialize({ ...model.settings, tcp_https_hostname: off, tcp_https_payload_file: null },
    model.interface).includes('https_hostname'), String(off));
for (const bad of [{}, 5, ['a'], true])
  assert.throws(() => config.serialize({ ...model.settings, tcp_https_hostname: bad, tcp_https_payload_file: null },
    model.interface), /tcp\.https_hostname/);
// A JSONMap section renders the rows found under a model key of the same name:
// `interface` comes from config.parse, so anything else must be assigned in the
// view. Without it the table shows up empty and the next save drops the entries.
{
  const provided = Object.keys(config.parse(original));
  let seen = 0;
  for (const match of viewSource.matchAll(/m\.section\(form\.TableSection,\s*'([a-z_]+)'/g)) {
    seen++;
    const name = match[1];
    if (provided.includes(name)) continue;
    assert(new RegExp('model\\.' + name + '\\s*=').test(viewSource),
      `JSONMap 段 ${name} 的行没有挂到 model.${name}，页面重载后会丢数据`);
  }
  assert(seen >= 1, '至少有监听接口这一个数组表段');
}
// Check syntax of the view and every shipped JSON file too.
new Function(fs.readFileSync('packaging/luci/htdocs/luci-static/resources/view/fakeflow.js', 'utf8'));
// The status poll must skip while the page is hidden — LuCI's own poll never looks
// at document.hidden, and every tick costs the router about ten process spawns —
// and it must refresh immediately when the tab comes back instead of waiting.
assert(/visibilityState/.test(viewSource) && /visibilitychange/.test(viewSource),
  '轮询需要在页面隐藏时跳过，并在回到前台时立即刷新一次');
for (const path of ['luci/menu.d', 'rpcd/acl.d'])
  JSON.parse(fs.readFileSync(`packaging/luci/root/usr/share/${path}/luci-app-fakeflow.json`, 'utf8'));
// Read-side retry of rpcd's config lock: rpcd acquires the lock before doing any
// work, so 正在执行/锁繁忙 means nothing happened and the same call may be repeated.
assert.equal(config.transient('另一个配置操作正在执行，请稍后重试。'), true);
assert.equal(config.transient('配置锁繁忙，请稍后重试。'), true);
for (const other of ['配置已保存并应用。', '配置已被其他页面或终端修改，请重新加载后再保存。', '', null, undefined])
  assert.equal(config.transient(other), false, String(other));
let lockCalls = 0;
const flaky = () => {
  lockCalls++;
  return Promise.resolve(lockCalls < 3
    ? { ok: false, message: '另一个配置操作正在执行，请稍后重试。' }
    : { ok: true, message: '配置已保存并应用。' });
};
config.retry(flaky, 4, 1).then(result => {
  assert.equal(result.ok, true, '被锁挡住后最终应成功');
  assert.equal(lockCalls, 3, '应重试到第三次（前两次被锁挡住）');
  let fatalCalls = 0;
  const fatal = () => { fatalCalls++; return Promise.resolve({ ok: false, message: '配置无效。' }); };
  return config.retry(fatal, 3, 1).then(failed => {
    assert.equal(failed.ok, false);
    assert.equal(fatalCalls, 1, '非锁错误不得重试');
    console.log('LuCI config roundtrip, boundaries, custom payloads, second TCP template, injection rejection, lock retry and visibility passed.');
  });
}).catch(error => { console.error(error); process.exitCode = 1; });
