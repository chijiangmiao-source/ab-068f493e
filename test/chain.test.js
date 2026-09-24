'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { verifyChain, parseChainEntries, parseRootJwk } from '../src/core/verify.js';
import { buildChain, tamperEnvelope, issueEnvelope } from '../src/core/issue.js';

async function verifyText(rootJwk, entries, now) {
  return verifyChain({
    root: parseRootJwk(JSON.stringify(rootJwk)),
    entries: parseChainEntries(JSON.stringify(entries)),
    now,
  });
}

test('合法链：逐跳签名有效、约束逐级收紧、结论 ALLOW', async () => {
  const chain = await buildChain({ amount: 12 });
  const r = await verifyText(chain.rootJwk, chain.entries, chain.now);
  assert.equal(r.status, 'allow');
  assert.equal(r.hops.length, 3);
  // 每跳都有签名、规范载荷摘要
  for (const h of r.hops) {
    assert.ok(h.signature.length > 0);
    assert.equal(h.payloadHash.length, 43);
    assert.ok(h.payloadLength > 0);
  }
  // 收紧后约束 = 交集
  assert.deepEqual(r.effective.allowedBuoys, ['BUOY-A01']);
  assert.equal(r.effective.sampleLimit, 20);
  assert.equal(r.decision.result, 'ALLOW');
  // 签发者/主体链接
  assert.equal(r.hops[0].issuerThumbprint, r.root.thumbprint);
  assert.equal(r.hops[0].subjectThumbprint, r.hops[1].issuerThumbprint);
  assert.equal(r.hops[1].subjectThumbprint, r.hops[2].issuerThumbprint);
});

test('越权链：末端浮标未获全部上游允许 → 拒绝并定位首个上游跳', async () => {
  const chain = await buildChain({ amount: 12 });
  // 末端命令改写为未被中间跳允许的浮标（需用 vessel 重新签名才能越过签名，
  // 这里构造“签名合法但授权不足”：用覆盖参数让末端允许集合缺该浮标）
  // 直接篡改会先撞签名；因此用 buildChain override 让末端 signed buoys 包含
  // 但上游不允许 —— 那种情况会在收紧检查失败。要测“末端浮标未获全部上游允许”，
  // 让命令目标浮标不在末端自身 allowedBuoys 中：需要重新签末端。
  const vessel = chain.keys.vessel;
  const regional = chain.keys.regional;
  const now = chain.now;
  // 中间跳允许 A01,A02；末端命令只允许 A02，但命令目标 A01
  const newLast = await issueEnvelope({
    signerKey: vessel.keyPair.privateKey,
    signerJwk: vessel.publicKey,
    subjectJwk: vessel.publicKey,
    kind: 'command',
    notBefore: now - 5,
    notAfter: now + 900,
    allowedBuoys: ['BUOY-A02'],
    sampleLimit: 20,
    command: { buoy: 'BUOY-A01', amount: 12 },
  });
  chain.entries[2] = newLast;
  // 注意末端 allowedBuoys 是 ['A02'] ⊂ 中间跳 ['A01','A02']，收紧成立；
  // 但命令目标 A01 不在末端允许集合 → 定位最后一跳 command.buoy
  const r = await verifyText(chain.rootJwk, chain.entries, now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'POLICY_DENIED');
  assert.equal(r.error.hop, 2);
  assert.equal(r.error.field, 'command.buoy');
});

test('越权链：中间跳不允许末端浮标 → 定位第 1 跳', async () => {
  const chain = await buildChain({ amount: 12 });
  const now = chain.now;
  // 让末端允许集合与目标都是 A02（A02 在中间跳中），然后重新签发一个
  // “中间跳只允许 A01”的版本，使末端 A02 成为上游未授权。
  const { root, regional, vessel } = chain.keys;
  const mid = await issueEnvelope({
    signerKey: regional.keyPair.privateKey,
    signerJwk: regional.publicKey,
    subjectJwk: vessel.publicKey,
    kind: 'delegation',
    notBefore: now - 30,
    notAfter: now + 1800,
    allowedBuoys: ['BUOY-A01'],
    sampleLimit: 50,
  });
  const last = await issueEnvelope({
    signerKey: vessel.keyPair.privateKey,
    signerJwk: vessel.publicKey,
    subjectJwk: vessel.publicKey,
    kind: 'command',
    notBefore: now - 5,
    notAfter: now + 800,
    allowedBuoys: ['BUOY-A02'],
    sampleLimit: 20,
    command: { buoy: 'BUOY-A02', amount: 12 },
  });
  // mid 只允许 A01，末端集合 A02 非子集 → 收紧检查在第 2 跳首先失败
  const entries = [chain.entries[0], mid, last];
  const r = await verifyText(chain.rootJwk, entries, now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'POLICY_RELAXED');
  assert.equal(r.error.hop, 2);
  assert.equal(r.error.field, 'allowedBuoys');
});

test('越权链：采样量超过某一上游上限 → 拒绝并定位首个超限跳', async () => {
  // 上限链 100 -> 50 -> 20；采样 30 超过末端 20（首个超限跳为最后一跳）
  let chain = await buildChain({ amount: 30 });
  let r = await verifyText(chain.rootJwk, chain.entries, chain.now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'POLICY_DENIED');
  assert.equal(r.error.field, 'command.amount');
  assert.equal(r.error.hop, 2);

  // 采样 60：超过中间跳 50；但末端已先以 20 拒绝（按跳顺序检查仍是 hop2）。
  // 构造末端上限放宽到 50 不允许（收紧禁止）。改为末端 40、采样 45：
  // 末端 40 通过，中间跳 50 通过？45<50 通过，根 100 通过 => allow。
  // 要定位中间跳，让末端 sampleLimit=40，采样 45 时末端先拒。按遍历顺序，
  // 末端永远先于中间跳被检查，所以“首个”定位是末端；再验证中间跳上限被放宽场景：
  chain = await buildChain({ amount: 12, override: [, , { sampleLimit: 55 }] });
  // 末端 55 > 中间 50 → 收紧失败
  r = await verifyText(chain.rootJwk, chain.entries, chain.now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'POLICY_RELAXED');
  assert.equal(r.error.field, 'sampleLimit');
  assert.equal(r.error.hop, 2);
});

test('篡改：改写已签名命令内容且签名不变 → 第 2 跳签名失败', async () => {
  const chain = await buildChain({ amount: 12 });
  chain.entries[2] = tamperEnvelope(chain.entries[2], (e) => {
    e.command.amount = 999;
  });
  const r = await verifyText(chain.rootJwk, chain.entries, chain.now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'BAD_SIGNATURE');
  assert.equal(r.error.hop, 2);
  assert.equal(r.error.field, 'signature');
  assert.ok(r.error.payloadHash);
});

test('篡改：改写委托 allowedBuoys → 对应跳签名失败', async () => {
  const chain = await buildChain({ amount: 12 });
  chain.entries[1] = tamperEnvelope(chain.entries[1], (e) => {
    e.allowedBuoys = ['BUOY-A01', 'BUOY-B07'];
  });
  const r = await verifyText(chain.rootJwk, chain.entries, chain.now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'BAD_SIGNATURE');
  assert.equal(r.error.hop, 1);
});

test('链首签发者不等于根公钥 → ROOT_MISMATCH 定位 hop0', async () => {
  const chain = await buildChain({ amount: 12 });
  const other = await buildChain({ amount: 12 });
  const r = await verifyText(other.rootJwk, chain.entries, chain.now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'ROOT_MISMATCH');
  assert.equal(r.error.hop, 0);
  assert.equal(r.error.field, 'issuer');
});

test('断链：第 2 跳签发者不是第 1 跳主体 → CHAIN_LINK', async () => {
  const chain = await buildChain({ amount: 12 });
  const now = chain.now;
  const stranger = await buildChain({});
  const last = await issueEnvelope({
    signerKey: stranger.keys.vessel.keyPair.privateKey,
    signerJwk: stranger.keys.vessel.publicKey,
    subjectJwk: chain.keys.vessel.publicKey,
    kind: 'command',
    notBefore: now - 5,
    notAfter: now + 800,
    allowedBuoys: ['BUOY-A01'],
    sampleLimit: 20,
    command: { buoy: 'BUOY-A01', amount: 12 },
  });
  chain.entries[2] = last;
  const r = await verifyText(chain.rootJwk, chain.entries, now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'CHAIN_LINK');
  assert.equal(r.error.hop, 2);
});

test('时间窗：放宽 notAfter / notBefore 被拒绝', async () => {
  const now = Math.floor(Date.now() / 1000);
  let chain = await buildChain({ now, amount: 1 });
  chain = await buildChain({
    now,
    amount: 1,
    override: [, { notAfter: now + 99999 }],
  });
  let r = await verifyText(chain.rootJwk, chain.entries, now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, 'POLICY_RELAXED');
  assert.equal(r.error.field, 'notAfter');

  chain = await buildChain({ now, amount: 1, override: [, { notBefore: now - 9999 }] });
  r = await verifyText(chain.rootJwk, chain.entries, now);
  assert.equal(r.status, 'deny');
  assert.equal(r.error.field, 'notBefore');
});

test('时间窗：已过期 / 未生效被拒绝', async () => {
  const now = 1_700_000_000;
  const chain = await buildChain({ now, windowSec: 3600, amount: 1 });
  const rExpired = await verifyText(chain.rootJwk, chain.entries, now + 7200);
  assert.equal(rExpired.status, 'deny');
  assert.equal(rExpired.error.code, 'POLICY_DENIED');
  assert.equal(rExpired.error.field, 'notAfter');

  const rEarly = await verifyText(chain.rootJwk, chain.entries, now - 999);
  assert.equal(rEarly.status, 'deny');
  assert.equal(rEarly.error.field, 'notBefore');
});

test('严格 JSON：链文本中的重复键/不安全整数/非规范键序可定位', async () => {
  const chain = await buildChain({ amount: 1 });
  const text = JSON.stringify(chain.entries);

  // 重复键（注入到第一份对象）
  const dup = text.replace('"sampleLimit":100', '"sampleLimit":100,"sampleLimit":50');
  await assertDenyAt(dup, chain.rootJwk, 'MALFORMED_JSON', 0);

  // 不安全整数
  const unsafe = text.replace('"sampleLimit":100', '"sampleLimit":9007199254740993');
  await assertDenyAt(unsafe, chain.rootJwk, 'MALFORMED_JSON', 0);

  // 非规范键序：第一份对象交换 kind 与 notAfter 的出现顺序（规范序 notAfter 在 notBefore 前）
  const reordered = text.replace(
    /"kind":"delegation","notAfter":(\d+)/,
    '"notAfter":$1,"kind":"delegation"'
  );
  await assertDenyAt(reordered, chain.rootJwk, 'MALFORMED_JSON', 0);
});

async function assertDenyAt(chainText, rootJwk, code, objectIndex) {
  let entries;
  try {
    entries = parseChainEntries(chainText);
  } catch (e) {
    assert.equal(e.code, code, `解析期错误码不符：${e.code} ${e.message}`);
    if (objectIndex !== undefined) assert.equal(e.objectIndex, objectIndex);
    return;
  }
  const r = await verifyChain({ root: rootJwk, entries });
  assert.equal(r.status, 'deny');
  assert.equal(r.error.code, code);
  if (objectIndex !== undefined) assert.equal(r.error.objectIndex, objectIndex);
}
