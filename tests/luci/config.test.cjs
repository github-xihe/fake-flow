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
// The same trap applies to the [[tcp.extra]] table's options, which the view
// creates with option(): every one whose default is empty must accept it.
for (const [key, spec] of Object.entries(config.extra_fields)) {
  if (spec[1] !== '') continue;
  const idx = viewSource.search(new RegExp("option\\(form\\.(Value|ListValue), '" + key + "'"));
  assert(idx >= 0, key + ' 未在 [[tcp.extra]] 表单中创建');
  assert(viewSource.slice(idx, idx + 500).includes('rmempty = true'),
    key + ' 在 [[tcp.extra]] 里默认值为空，必须设 rmempty = true');
}
// [[tcp.extra]]: an array of tables, each entry its own port-matched template.
const extra = structuredClone(model);
extra.settings.tcp_extras = [
  { hostname:'cdn.example', payload:'tls', payload_file:'', ports:'8080' },
  { hostname:'plain.example', payload:'http', payload_file:'', ports:'8000, 8001' }
];
text = config.serialize(extra.settings, extra.interface);
assert.equal(text.split('[[tcp.extra]]').length, 3, 'one table per entry');
assert(text.includes('hostname = "cdn.example"') && text.includes('payload = "tls"'));
assert(text.includes('payload = "http"') && text.includes('ports = [8000, 8001]'));
assert(text.indexOf('[[tcp.extra]]') < text.indexOf('[udp]'),
  'the array belongs to [tcp]: a key after it would land in the last entry');
assert.deepEqual(roundtrip(extra), extra);
// A payload file replaces the generated kind, so neither hostname nor payload is
// written and the parser cannot see a conflicting pair.
const filed = structuredClone(model);
filed.settings.tcp_extras = [
  { hostname:'', payload:'tls', payload_file:'/etc/fakehttp/extra.bin', ports:'9000' }
];
text = config.serialize(filed.settings, filed.interface);
const filedBlock = text.slice(text.indexOf('[[tcp.extra]]'), text.indexOf('[udp]'));
assert(filedBlock.includes('payload_file = "/etc/fakehttp/extra.bin"'));
assert(!filedBlock.includes('hostname = ') && !filedBlock.includes('payload = '),
  'a payload file replaces both the hostname and the generated kind');
assert(filedBlock.includes('ports = [9000]'));
assert.deepEqual(roundtrip(filed), filed);
// Three port-matched templates in total, https_* included.
const three = structuredClone(extra);
three.settings.tcp_extras.push({ hostname:'third.example', payload:'tls', payload_file:'', ports:'7000' });
assert.deepEqual(roundtrip(three), three);
for (const settings of [
  { ...three.settings, tcp_https_hostname:'tls.example' },                                    // https + three
  { ...extra.settings, tcp_extras:[...extra.settings.tcp_extras, ...extra.settings.tcp_extras] },
  { ...extra.settings, tcp_extras:[{ hostname:'a', payload:'tls', payload_file:'', ports:'8080' },
                                  { hostname:'b', payload:'tls', payload_file:'', ports:'8080' }] },
  { ...extra.settings, tcp_https_hostname:'tls.example', tcp_https_ports:'8080' },             // collides with entry 1
  { ...extra.settings, tcp_https_hostname:'tls.example',
    tcp_extras:[{ hostname:'a', payload:'tls', payload_file:'', ports:'443' }] },                // collides on the 443 default
  { ...extra.settings, tcp_extras:[{ hostname:'', payload:'tls', payload_file:'', ports:'8080' }] },
  { ...extra.settings, tcp_extras:[{ hostname:'a', payload:'tls', payload_file:'/tmp/x', ports:'8080' }] },
  { ...extra.settings, tcp_extras:[{ hostname:'a', payload:'sip', payload_file:'', ports:'8080' }] },
  { ...extra.settings, tcp_extras:[{ hostname:'a', payload:'tls', payload_file:'', ports:'' }] },
  { ...extra.settings, tcp_extras:[{ hostname:'a', payload:'tls', payload_file:'', ports:'0' }] },
  { ...extra.settings, tcp_extras:[{ hostname:'a', payload:'tls', payload_file:'', ports:'8080, 8080' }] }
]) assert.throws(() => config.serialize(settings, extra.interface));
// The same rules as text, plus duplicate and unknown keys inside an entry.
const entry = '\n[[tcp.extra]]\nhostname = "a"\npayload = "http"\nports = [8080]\n';
const parsed = config.parse(original + entry);
assert.equal(parsed.settings.tcp_extras.length, 1);
assert.equal(parsed.settings.tcp_extras[0].hostname, 'a');
assert.equal(parsed.settings.tcp_extras[0].ports, '8080');
for (const bad of [
  '\n[[tcp.extra]]\nhostname = "a"\n',
  '\n[[tcp.extra]]\nhostname = "a"\nports = []\n',
  '\n[[tcp.extra]]\nhostname = "a"\nports = [8080,]\n',
  '\n[[tcp.extra]]\nhostname = "a"\nports = [8080]\nports = [8081]\n',
  '\n[[tcp.extra]]\nunknown = 1\n',
  '\n[[tcp.extra]]\nhostname = "a"\npayload = "sip"\nports = [8080]\n',
  '\n[[tcp.extra]]\nhostname = "a"\nhostname = "b"\nports = [8080]\n'
]) assert.throws(() => config.parse(original + bad));
// A port that the https_* template already owns (443 is its default) cannot be
// claimed by an entry: the first match would hide the entry.
assert.throws(() => config.parse(original.replace(ht, ht + '\nhttps_hostname = "h"') +
  '\n[[tcp.extra]]\nhostname = "a"\nports = [443]\n'));
assert.throws(() => config.parse(original + entry.repeat(4)));
// Check syntax of the view and every shipped JSON file too.
new Function(fs.readFileSync('packaging/luci/htdocs/luci-static/resources/view/fakeflow.js', 'utf8'));
for (const path of ['luci/menu.d', 'rpcd/acl.d'])
  JSON.parse(fs.readFileSync(`packaging/luci/root/usr/share/${path}/luci-app-fakeflow.json`, 'utf8'));
console.log('LuCI config roundtrip, boundaries, custom payloads, [[tcp.extra]] slots and injection rejection passed.');
