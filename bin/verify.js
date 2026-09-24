#!/usr/bin/env node
'use strict';
// 一次性验收服务 verify：
//   1) 复核合法链的逐跳证据（签名、收紧约束、规范载荷摘要、ALLOW）
//   2) 复核越权链的拒绝结果（定位首个限制字段/跳）
//   3) 复核篡改签名的拒绝结果（定位签名失败跳）
//   4) 复核“错误草稿不覆盖上一份有效证据”
//   5) 运行代码测试（node --test）
//   6) 页面构建检查（scripts/build-check.js）
//   7) 健康地址 API/HTTP 冒烟（启动真实 HTTP 服务，打 /healthz 与 /api/verify）
// 执行完毕即退出，退出码 0=全部通过，1=存在失败。

import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyChain } from '../src/core/verify.js';
import { buildChain, tamperEnvelope } from '../src/core/issue.js';
import { startServer } from '../src/server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const results = [];
function check(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(
      (detail = '') => {
        results.push({ name, ok: true, detail });
        console.log(`  ✅ ${name}${detail ? ` — ${detail}` : ''}`);
      },
      (err) => {
        results.push({ name, ok: false, detail: err.message });
        console.log(`  ❌ ${name} — ${err.message}`);
        if (process.env.VERIFY_DEBUG && err.stack) console.log(err.stack);
      }
    );
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function section(title, fn) {
  console.log(`\n=== ${title} ===`);
  await fn();
}

async function acceptanceChainChecks() {
  await section('1. 合法链逐跳证据复核', async () => {
    const now = Math.floor(Date.now() / 1000);
    const chain = await buildChain({ now, amount: 12 });

    await check('合法链结论为 ALLOW', async () => {
      const r = await verifyChain({ root: chain.rootJwk, entries: chain.entries, now });
      assert(r.status === 'allow', `expected allow, got ${r.status}: ${r.error?.message}`);
      assert(r.decision.result === 'ALLOW', 'decision.result 不是 ALLOW');
    });

    await check('每跳签名与规范载荷摘要齐全', async () => {
      const r = await verifyChain({ root: chain.rootJwk, entries: chain.entries, now });
      assert(r.hops.length === chain.entries.length, '跳数不符');
      r.hops.forEach((h, i) => {
        assert(typeof h.signature === 'string' && h.signature.length > 0, `第 ${i} 跳缺少签名`);
        // P-256 r||s 为 64 字节，base64url 去填充后为 86 字符
        assert(/^[A-Za-z0-9_-]{86}$/.test(h.signature), `第 ${i} 跳签名不是 P-256 r||s base64url(64B)`);
        assert(h.payloadHash.length === 43, `第 ${i} 跳载荷摘要长度异常`);
        assert(h.payloadLength > 0, `第 ${i} 跳载荷长度为 0`);
      });
    });

    await check('签发者—主体逐跳链接成立', async () => {
      const r = await verifyChain({ root: chain.rootJwk, entries: chain.entries, now });
      assert(r.hops[0].issuerThumbprint === r.root.thumbprint, '链首签发者不是根公钥');
      for (let i = 1; i < r.hops.length; i++) {
        assert(
          r.hops[i].issuerThumbprint === r.hops[i - 1].subjectThumbprint,
          `第 ${i} 跳签发者 != 第 ${i - 1} 跳主体`
        );
      }
    });

    await check('收紧后约束为逐级交集', async () => {
      const r = await verifyChain({ root: chain.rootJwk, entries: chain.entries, now });
      assert(r.status === 'allow', '合法链应允许');
      assert(r.effective.sampleLimit === 20, `有效上限应为 20，实际 ${r.effective.sampleLimit}`);
      assert(JSON.stringify(r.effective.allowedBuoys) === JSON.stringify(['BUOY-A01']), '有效浮标集合应为 [BUOY-A01]');
      assert(r.effective.notBefore >= now - 10 && r.effective.notAfter <= now + 3600, '有效时间窗未收紧');
    });
  });

  await section('2. 越权链拒绝复核', async () => {
    const now = Math.floor(Date.now() / 1000);

    await check('采样量超过末端上限 → 拒绝并定位 command.amount / 末跳', async () => {
      const chain = await buildChain({ now, amount: 30 }); // 末端上限 20
      const r = await verifyChain({ root: chain.rootJwk, entries: chain.entries, now });
      assert(r.status === 'deny', '应拒绝');
      assert(r.error.code === 'POLICY_DENIED', `错误码应为 POLICY_DENIED，实际 ${r.error.code}`);
      assert(r.error.hop === 2, `应定位第 2 跳，实际 ${r.error.hop}`);
      assert(r.error.field === 'command.amount', `应定位 command.amount，实际 ${r.error.field}`);
    });

    await check('放宽采样上限 → POLICY_RELAXED 定位 sampleLimit', async () => {
      const chain = await buildChain({ now, amount: 1, override: [, , { sampleLimit: 55 }] });
      const r = await verifyChain({ root: chain.rootJwk, entries: chain.entries, now });
      assert(r.status === 'deny', '应拒绝');
      assert(r.error.code === 'POLICY_RELAXED', `实际 ${r.error.code}`);
      assert(r.error.field === 'sampleLimit', `实际 ${r.error.field}`);
    });

    await check('链首签发者不等于根公钥 → ROOT_MISMATCH hop0', async () => {
      const chain = await buildChain({ now });
      const other = await buildChain({ now });
      const r = await verifyChain({ root: other.rootJwk, entries: chain.entries, now });
      assert(r.status === 'deny' && r.error.code === 'ROOT_MISMATCH', '应 ROOT_MISMATCH');
      assert(r.error.hop === 0 && r.error.field === 'issuer', '定位错误');
    });
  });

  await section('3. 篡改签名拒绝复核', async () => {
    const now = Math.floor(Date.now() / 1000);
    const chain = await buildChain({ now, amount: 12 });
    chain.entries[2] = tamperEnvelope(chain.entries[2], (e) => {
      e.command.amount = 999;
    });
    await check('改写已签名命令内容且签名不变 → BAD_SIGNATURE 定位末跳', async () => {
      const r = await verifyChain({ root: chain.rootJwk, entries: chain.entries, now });
      assert(r.status === 'deny', '应拒绝');
      assert(r.error.code === 'BAD_SIGNATURE', `实际 ${r.error.code}`);
      assert(r.error.hop === 2, `应定位第 2 跳，实际 ${r.error.hop}`);
      assert(r.error.field === 'signature', '应定位 signature 字段');
      assert(r.error.payloadHash, '应给出规范载荷摘要');
    });
  });
}

async function evidenceIsolationCheck() {
  await section('4. 错误草稿不得覆盖上一份有效证据', async () => {
    const dir = path.join(ROOT, 'data', 'evidence');
    await fs.mkdir(dir, { recursive: true });
    const before = new Set(await fs.readdir(dir));

    // 通过 API 先走一条合法链，再走篡改链（见 HTTP 冒烟），
    // 这里在文件层面复核：denied/ 有新增而 evidence/ 无新增覆盖。
    await check('证据目录可写', async () => {
      await fs.access(dir);
    });

    const deniedDir = path.join(ROOT, 'data', 'denied');
    await fs.mkdir(deniedDir, { recursive: true });
    const deniedBefore = new Set(await fs.readdir(deniedDir));

    // HTTP 冒烟会产生 allow + deny 两个请求
    globalThis.__evidenceBefore = before;
    globalThis.__deniedBefore = deniedBefore;
  });
}

function runNodeProcess(args, name) {
  const res = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8' });
  const output = `${res.stdout || ''}${res.stderr || ''}`;
  if (res.status !== 0) {
    const err = new Error(`${name} 退出码 ${res.status}\n${output.split('\n').slice(-25).join('\n')}`);
    err.output = output;
    throw err;
  }
  return output;
}

async function testAndBuildChecks() {
  await section('5. 代码测试（node --test test/）', async () => {
    await check('全部单元/集成测试通过', async () => {
      const out = runNodeProcess(['--test', 'test/'], 'node --test');
      const m = /# tests\s+(\d+)/.exec(out);
      const pass = /# pass\s+(\d+)/.exec(out);
      const fail = /# fail\s+(\d+)/.exec(out);
      assert(fail && fail[1] === '0', '存在失败测试');
      return `${pass?.[1] || m?.[1] || '?'} 项测试通过`;
    });
  });

  await section('6. 页面构建检查', async () => {
    await check('语法/静态资源/模块导入检查通过', async () => {
      const out = runNodeProcess(['scripts/build-check.js'], 'build-check');
      const m = /全部通过（(\d+) 个 JS/.exec(out);
      return m ? `${m[1]} 个 JS 文件检查通过` : '构建检查通过';
    });
  });
}

async function httpSmokeChecks() {
  await section('7. 健康地址 API/HTTP 冒烟', async () => {
    const port = Number(process.env.SMOKE_PORT || 18080);
    const { server } = await startServer(port, '127.0.0.1');
    const base = `http://127.0.0.1:${port}`;

    try {
      await check('GET /healthz 返回 200 status=ok', async () => {
        const res = await fetch(`${base}/healthz`);
        assert(res.status === 200, `HTTP ${res.status}`);
        const j = await res.json();
        assert(j.status === 'ok', `body.status=${j.status}`);
        assert(j.service === 'buoy-dcid-chain', '服务名不符');
      });

      await check('GET / 静态页面可访问', async () => {
        const res = await fetch(`${base}/`);
        assert(res.status === 200, `HTTP ${res.status}`);
        const html = await res.text();
        assert(html.includes('委托链验签'), '页面标题缺失');
      });

      await check('POST /api/verify 合法链 → allow', async () => {
        const chain = await buildChain({ amount: 5 });
        const res = await fetch(`${base}/api/verify`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ root: chain.rootJwk, chain: chain.entries }),
        });
        assert(res.status === 200, `HTTP ${res.status}`);
        const j = await res.json();
        assert(j.status === 'allow', `API 应返回 allow：${j.error?.message}`);
      });

      await check('POST /api/verify 篡改链 → deny（且不覆盖有效证据）', async () => {
        const chain = await buildChain({ amount: 5 });
        const tampered = await buildChain({ amount: 5 });
        tampered.entries[1] = tamperEnvelope(tampered.entries[1], (e) => {
          e.sampleLimit = 1; // 改写后保持原签名
        });
        const res = await fetch(`${base}/api/verify`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ root: tampered.rootJwk, chain: tampered.entries }),
        });
        const j = await res.json();
        assert(res.status === 200 && j.status === 'deny', '应返回 deny');
        assert(j.error.code === 'BAD_SIGNATURE', `实际 ${j.error.code}`);

        // 证据隔离复核
        const evDir = path.join(ROOT, 'data', 'evidence');
        const deDir = path.join(ROOT, 'data', 'denied');
        const evAfter = await fs.readdir(evDir);
        const deAfter = await fs.readdir(deDir);
        const newEvidence = evAfter.filter((f) => !globalThis.__evidenceBefore.has(f));
        const newDenied = deAfter.filter((f) => !globalThis.__deniedBefore.has(f));
        assert(newEvidence.length >= 1, '合法链应产生至少 1 份有效证据');
        assert(newDenied.length >= 1, '拒绝应在 denied/ 留痕');
        // 有效证据内容必须是 allow，不允许被 deny 草稿覆盖
        for (const f of newEvidence) {
          const txt = await fs.readFile(path.join(evDir, f), 'utf8');
          assert(txt.includes('"status": "allow"') || txt.includes('"status":"allow"'),
            `证据文件 ${f} 不是有效证据`);
        }
        return `新增有效证据 ${newEvidence.length} 份、拒绝留痕 ${newDenied.length} 份，未互相覆盖`;
      });

      await check('POST /api/verify 重复键输入 → 可定位 MALFORMED_JSON', async () => {
        const chain = await buildChain({ amount: 1 });
        const badChain = JSON.stringify(chain.entries).replace(
          '"sampleLimit":100',
          '"sampleLimit":100,"sampleLimit":50'
        );
        const res = await fetch(`${base}/api/verify`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ root: chain.rootJwk, chain: badChain }),
        });
        const j = await res.json();
        assert(j.status === 'deny' && j.error.code === 'MALFORMED_JSON', `实际 ${j.status}/${j.error?.code}`);
        assert(j.error.objectIndex === 0, '应定位第 0 份对象');
      });
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
}

async function main() {
  const t0 = Date.now();
  console.log('══════════════════════════════════════════════════════════');
  console.log(' 浮标离线受限委托链 · verify 一次性验收');
  console.log(` Node ${process.version} · ${new Date().toISOString()}`);
  console.log('══════════════════════════════════════════════════════════');

  await acceptanceChainChecks();
  await evidenceIsolationCheck();
  await testAndBuildChecks();
  await httpSmokeChecks();

  const failed = results.filter((r) => !r.ok);
  const passed = results.length - failed.length;
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  console.log('\n══════════════════════════════════════════════════════════');
  console.log(` 验收结果：${passed}/${results.length} 通过，${failed.length} 失败，用时 ${elapsed}s`);
  if (failed.length) {
    console.log(' 失败项：');
    for (const f of failed) console.log(`   - ${f.name}: ${f.detail}`);
  }
  console.log('══════════════════════════════════════════════════════════');
  process.exitCode = failed.length ? 1 : 0;
}

main().catch((e) => {
  console.error('verify 异常中断：', e);
  process.exit(2);
});
