"use strict";
/* Unit tests for the LuCI configuration module: the TOML subset it parses, the rule
 * table it writes and the static wiring of the view. Run: node tests/luci/config.test.cjs */
const fs = require("node:fs");
const assert = require("node:assert/strict");
const source = fs.readFileSync("packaging/luci/htdocs/luci-static/resources/fakeflow/config.js", "utf8");
const config = new Function("baseclass", source)({ extend: x => x });
const original = fs.readFileSync("config/fakeflow.toml", "utf8");
const model = config.parse(original);
const roundtrip = m => config.parse(config.serialize(m.settings, m.interface, m.rule));

/* round trip: the rule table is the model now, so it has to survive unchanged */
const rt = roundtrip(model);
assert.deepEqual(rt.rule, model.rule, "规则表往返必须一致");
assert.deepEqual(rt.settings, model.settings, "其余设置往返必须一致");
assert(model.rule.length >= 1 && model.rule[0].type === "http");

/* the rule table: order is the rotation order, disabled rows are kept */
const rules = [
  { enabled: "1", type: "http", payload: "one.example", comment: "first" },
  { enabled: "0", type: "tls", payload: "two.example", comment: "" },
  { enabled: "1", type: "custom", payload: "/etc/fakehttp/payload.tls", comment: "" }
];
const text = config.serialize(model.settings, model.interface, rules);
assert.equal((text.match(/\[\[tcp\.rule\]\]/g) || []).length, 3, "三条规则写三个块");
assert(text.indexOf('type = "http"') < text.indexOf('type = "tls"'), "顺序即轮换顺序");
assert(text.includes("enabled = false") && text.includes('comment = "first"'));
const tcpHead = text.split("[tcp]")[1].split("[[tcp.rule]]")[0];
assert(!/^\s*(payload|hostname|payload_file|https_)\w*\s*=/m.test(tcpHead),
  "旧的扁平键不再写出（迁移成规则）");
assert.equal((text.match(/^\s*payload = /gm) || []).length, 4, "三条规则各一个 payload，加 UDP 的一个");

/* LuCI cannot express "the payload column means a host name or a path depending on
 * the type", so the serializer refuses the wrong shapes instead. */
for (const [bad, why] of [
  [[{ enabled: "1", type: "http", payload: "" }], /域名不能为空/],
  [[{ enabled: "1", type: "custom", payload: "" }], /不能为空/],
  [[{ enabled: "1", type: "http", payload: "https://a.example" }], /裸域名/],
  [[{ enabled: "1", type: "tls", payload: "a.example:443" }], /裸域名/],
  [[{ enabled: "1", type: "tls", payload: "a.example/x" }], /裸域名/],
  [[{ enabled: "1", type: "custom", payload: "relative.bin" }], /绝对路径/],
  [[], /至少需要一条规则/],
  [[{ enabled: "0", type: "http", payload: "a.example" }], /至少要有一条启用/],
  [[{ enabled: "1", type: "http", payload: "a.example" },
    { enabled: "1", type: "http", payload: "b.example" },
    { enabled: "1", type: "http", payload: "c.example" },
    { enabled: "1", type: "http", payload: "d.example" }], /最多 3 条/]
]) assert.throws(() => config.serialize(model.settings, model.interface, bad), why);

/* a configuration written before the rule table existed still loads, and the next
 * save rewrites it as rules */
const legacy = 'version = 1\n[[interfaces]]\nname = "wan"\n[tcp]\npayload = "http"\n' +
  'hostname = "old.example"\nhttps_hostname = "old-tls.example"\nhttps_ports = [8443, 443]\n[udp]\n';
const migrated = config.parse(legacy);
assert.deepEqual(migrated.rule.map(r => [r.type, r.payload]),
  [["http", "old.example"], ["tls", "old-tls.example"]], "旧的 https_* 键变成第二条规则");
const legacyOut = config.serialize(migrated.settings, migrated.interface, migrated.rule);
assert(!/https_/.test(legacyOut), "保存时改写成规则表，不再写旧键");

/* parse errors */
for (const bad of [
  "version = 1\n", "[[interfaces]]\nname = \"wan\"\n",
  'version = 1\n[[interfaces]]\nname = "wan"\n[tcp]\nunknown = 1\n',
  'version = 1\n[[interfaces]]\nname = "wan"\n[[tcp.rule]]\ntype = "https"\npayload = "a.example"\n',
  'version = 1\n[[interfaces]]\nname = "wan"\n[[tcp.rule]]\ntype = "http"\npayload = "a.example"\npayload = "b.example"\n'
]) assert.throws(() => config.parse(bad), /无法转换为表单|需要 version/, bad);

/* view wiring: a JSONMap section renders the rows of the model key with the same
 * name, so every section needs that key assigned (or provided by parse) */
const viewSource = fs.readFileSync("packaging/luci/htdocs/luci-static/resources/view/fakeflow.js", "utf8");
new Function(viewSource);
const provided = Object.keys(config.parse(original));
for (const match of viewSource.matchAll(/m\.section\(form\.(\w+),\s*'([a-z_]+)'/g)) {
  if (provided.includes(match[2])) continue;
  assert(new RegExp("model\\." + match[2] + "\\s*=").test(viewSource),
    `JSONMap 段 ${match[2]} 的行没有挂到 model.${match[2]}，页面重载后会丢数据`);
}
assert(/m\.section\(form\.GridSection,\s*'rule'/.test(viewSource), "TCP 载荷规则要用表来编辑");
assert(/tbl\.addremove = true/.test(viewSource) && /tbl\.sortable = true/.test(viewSource),
  "规则表要能加行、能拖拽排序（顺序即轮换顺序）");
assert(/visibilityState/.test(viewSource) && /visibilitychange/.test(viewSource),
  "轮询需要在页面隐藏时跳过，并在回到前台时立即刷新一次");
for (const path of ["luci/menu.d", "rpcd/acl.d"])
  JSON.parse(fs.readFileSync(`packaging/luci/root/usr/share/${path}/luci-app-fakeflow.json`, "utf8"));

/* rpcd takes the config lock before doing any work, so a lock reply means nothing
 * happened and the read side may simply repeat the call */
let lockCalls = 0, failures = 0;
const flaky = () => {
  lockCalls++;
  if (failures--) return Promise.resolve({ ok: false, message: "另一个配置操作正在执行" });
  return Promise.resolve({ ok: true, value: lockCalls });
};
assert(config.transient("另一个配置操作正在执行") && config.transient("配置锁繁忙"));
assert(!config.transient("已保存") && !config.transient("") && !config.transient(null) && !config.transient(undefined));
failures = 2;
config.retry(flaky).then(r => {
  assert.equal(r.ok, true);
  assert.equal(lockCalls, 3, "两次锁冲突后第三次应当成功");
  let calls = 0;
  return config.retry(() => { calls++; return Promise.resolve({ ok: false, message: "接口名称无效。" }); })
    .then(r2 => { assert.equal(r2.ok, false); assert.equal(calls, 1, "非锁失败不重试"); });
}).then(() => {
  console.log("LuCI config roundtrip, rule table, legacy migration, rejection, lock retry and view wiring passed.");
});
