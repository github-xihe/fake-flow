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
// Check syntax of the view and every shipped JSON file too.
new Function(fs.readFileSync('packaging/luci/htdocs/luci-static/resources/view/fakeflow.js', 'utf8'));
for (const path of ['luci/menu.d', 'rpcd/acl.d'])
  JSON.parse(fs.readFileSync(`packaging/luci/root/usr/share/${path}/luci-app-fakeflow.json`, 'utf8'));
console.log('LuCI config roundtrip, boundaries, custom payloads and injection rejection passed.');
