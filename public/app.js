'use strict';
// 值班页面逻辑：直接复用与岸站同一套 src/core 代码（规范 JSON + P-256 逐跳验签）。

import { verifyChain, parseChainEntries, parseRootJwk } from '/src/core/verify.js';
import { buildChain, tamperEnvelope } from '/src/core/issue.js';

const $ = (id) => document.getElementById(id);
const rootInput = $('rootInput');
const chainInput = $('chainInput');
const verdict = $('verdict');
const hopsBox = $('hops');
const errorBox = $('errorBox');
const rawDetails = $('rawDetails');
const rawReport = $('rawReport');
const genStatus = $('genStatus');
const lastEvidence = $('lastEvidence');

const EVIDENCE_KEY = 'buoy-dcid.lastValidEvidence';

function short(s, n = 20) {
  if (!s) return '';
  return s.length <= n * 2 ? s : `${s.slice(0, n)}…${s.slice(-8)}`;
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function renderEvidence() {
  const raw = localStorage.getItem(EVIDENCE_KEY);
  lastEvidence.textContent = raw ?? '（尚无有效证据）';
}

function renderAllow(result) {
  verdict.className = 'verdict allow';
  verdict.innerHTML = `✅ 准许（ALLOW） · 验签时间 unix=${result.verifiedAt}<br>
    <span style="font-weight:400;font-size:12px">${esc(result.decision.reason)}</span>`;

  const eff = result.effective;
  hopsBox.innerHTML = `
    <div class="effective">
      <strong>收紧后的有效约束（全部跳交集）</strong>
      <dl class="kv">
        <dt>有效时间窗</dt><dd>${eff.notBefore} ~ ${eff.notAfter}（unix 秒）</dd>
        <dt>允许浮标</dt><dd>${eff.allowedBuoys.map(esc).join(', ')}</dd>
        <dt>采样上限</dt><dd>${eff.sampleLimit}</dd>
        <dt>末端命令</dt><dd>浮标 ${esc(result.decision.command.buoy)}，采样量 ${result.decision.command.amount}</dd>
        <dt>根公钥指纹</dt><dd class="mono">${esc(result.root.thumbprint)}</dd>
      </dl>
    </div>` +
    result.hops.map((h) => `
      <div class="hop">
        <div class="hop-head">
          <span class="hop-title">第 ${h.index} 跳 · ${h.kind === 'command' ? '末端命令' : '委托'}</span>
          <span class="badge ${h.kind}">${h.kind}</span>
        </div>
        <dl class="kv">
          <dt>签名（ECDSA P-256）</dt><dd class="mono">${esc(h.signature)}</dd>
          <dt>规范载荷摘要</dt><dd class="mono">sha256:${esc(h.payloadHash)}（${h.payloadLength} 字节）</dd>
          <dt>载荷字节预览</dt><dd class="mono">${esc(h.payloadPreview)}…</dd>
          <dt>签发者指纹</dt><dd class="mono">${esc(h.issuerThumbprint)}</dd>
          <dt>主体指纹</dt><dd class="mono">${esc(h.subjectThumbprint)}</dd>
          <dt>本跳时间窗</dt><dd>${h.constraints.notBefore} ~ ${h.constraints.notAfter}</dd>
          <dt>本跳允许浮标</dt><dd>${h.constraints.allowedBuoys.map(esc).join(', ')}</dd>
          <dt>本跳采样上限</dt><dd>${h.constraints.sampleLimit}</dd>
        </dl>
      </div>`).join('');

  errorBox.classList.add('hidden');
}

function renderDeny(result) {
  verdict.className = 'verdict deny';
  verdict.textContent = '⛔ 拒绝（DENY）';
  hopsBox.innerHTML = '';
  const e = result.error || {};
  const locParts = [];
  if (e.objectIndex !== undefined && e.objectIndex >= 0) locParts.push(`第 ${e.objectIndex} 份对象`);
  if (e.hop !== undefined) locParts.push(`第 ${e.hop} 跳`);
  if (e.field) locParts.push(`首个限制字段 ${e.field}`);
  if (e.path) locParts.push(`位置 ${e.path}`);
  if (e.line !== undefined) locParts.push(`行 ${e.line} 列 ${e.column}`);
  errorBox.classList.remove('hidden');
  errorBox.innerHTML = `
    <div><strong>${esc(e.code || 'ERROR')}</strong></div>
    <div>${esc(e.message || '验签失败')}</div>
    ${locParts.length ? `<div class="loc">定位：${locParts.map(esc).join(' · ')}</div>` : ''}`;
}

async function runVerifyLocally() {
  genStatus.textContent = '正在逐跳验签…';
  let result;
  try {
    const rootJwk = parseRootJwk(rootInput.value);
    const entries = parseChainEntries(chainInput.value);
    result = await verifyChain({ root: rootJwk, entries });
  } catch (e) {
    result = {
      status: 'deny',
      error: {
        code: e.code || 'VERIFY_ERROR',
        message: e.message,
        hop: e.hop,
        field: e.field,
        path: e.path,
        objectIndex: e.objectIndex,
        line: e.line,
        column: e.column,
      },
    };
  }

  rawDetails.classList.remove('hidden');
  rawReport.textContent = JSON.stringify(result, null, 2);

  if (result.status === 'allow') {
    renderAllow(result);
    // 关键：只有全部通过的有效证据才会覆盖上一份；拒绝草稿不落此存储。
    localStorage.setItem(
      EVIDENCE_KEY,
      JSON.stringify(
        {
          savedAt: new Date().toISOString(),
          rootThumbprint: result.root.thumbprint,
          command: result.decision.command,
          effective: result.effective,
          hopSignatures: result.hops.map((h) => ({ hop: h.index, signature: h.signature, payloadHash: h.payloadHash })),
        },
        null,
        2
      )
    );
  } else {
    renderDeny(result);
  }
  renderEvidence();
  genStatus.textContent = result.status === 'allow' ? '验签完成：准许。' : '验签完成：已拒绝，上一份有效证据保持不变。';
}

async function fillSample(kind) {
  genStatus.textContent = '正在离线生成演示密钥与签名链…';
  await new Promise((r) => setTimeout(r, 10));
  const now = Math.floor(Date.now() / 1000);
  let chain;
  if (kind === 'valid') {
    chain = await buildChain({ now, amount: 12 });
  } else if (kind === 'overlimit') {
    // 采样量超过中间跳/末端上限（20、50），但低于根上限 100：应定位到首个超限上游跳
    chain = await buildChain({ now, amount: 30 });
  } else {
    chain = await buildChain({ now, amount: 12 });
    // 改写最后一份已签名委托后的命令浮标，签名保持不变 → 签名失败跳
    chain.entries[2] = tamperEnvelope(chain.entries[2], (env) => {
      env.command.buoy = 'BUOY-X99';
    });
  }
  rootInput.value = JSON.stringify(chain.rootJwk);
  chainInput.value = JSON.stringify(chain.entries, null, 2);
  genStatus.textContent = '演示链已填入（离线私钥仅存在于本次生成过程，页面不保存）。';
}

async function checkHealth() {
  const el = $('health');
  try {
    const r = await fetch('/healthz');
    const j = await r.json();
    if (r.ok && j.status === 'ok') {
      el.textContent = `岸站在线 · ${j.time}`;
      el.className = 'health ok';
      return;
    }
    throw new Error('bad status');
  } catch {
    el.textContent = '岸站健康检查失败（页面仍可离线验签）';
    el.className = 'health bad';
  }
}

$('verifyBtn').addEventListener('click', runVerifyLocally);
$('sampleValidBtn').addEventListener('click', () => fillSample('valid'));
$('sampleOverLimitBtn').addEventListener('click', () => fillSample('overlimit'));
$('sampleTamperBtn').addEventListener('click', () => fillSample('tamper'));
$('clearBtn').addEventListener('click', () => {
  rootInput.value = '';
  chainInput.value = '';
  verdict.innerHTML = '';
  hopsBox.innerHTML = '';
  errorBox.classList.add('hidden');
  rawDetails.classList.add('hidden');
  genStatus.textContent = '';
});

renderEvidence();
checkHealth();
