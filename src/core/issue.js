'use strict';
// 离线签发辅助：构造规范信封并用 P-256 私钥签名（模拟“离线签发”的 U 盘工具）。
// 仅用于生成演示/验收夹具与测试；值班页面本身不持有任何私钥。

import { canonicalize, strictParse } from './canonical.js';
import { generateP256, signRaw } from './jwk.js';

/**
 * 签发一份信封。
 * @param {object} args
 * @param {CryptoKey} args.signerKey  签发者私钥
 * @param {object}    args.signerJwk  签发者公钥 JWK
 * @param {object}    args.subjectJwk 主体公钥 JWK
 * @param {"delegation"|"command"} args.kind
 * @param {number} args.notBefore
 * @param {number} args.notAfter
 * @param {string[]} args.allowedBuoys
 * @param {number} args.sampleLimit
 * @param {{buoy:string,amount:number}} [args.command]
 * @returns 规范键序、带 signature 的信封对象
 */
export async function issueEnvelope({
  signerKey,
  signerJwk,
  subjectJwk,
  kind,
  notBefore,
  notAfter,
  allowedBuoys,
  sampleLimit,
  command,
}) {
  const envelope = {
    allowedBuoys: [...allowedBuoys],
    issuer: { crv: 'P-256', kty: 'EC', x: signerJwk.x, y: signerJwk.y },
    kind,
    notAfter,
    notBefore,
    sampleLimit,
    subject: { crv: 'P-256', kty: 'EC', x: subjectJwk.x, y: subjectJwk.y },
  };
  if (kind === 'command') {
    envelope.command = { amount: command.amount, buoy: command.buoy };
  }
  const bytes = canonicalize(envelope);
  const signature = await signRaw(signerKey, bytes);
  const signed = { ...envelope, signature };
  // 返回“规范字节再解析”的对象：保证随后 JSON.stringify 输出仍为同一套规范字节
  return strictParse(new TextDecoder().decode(canonicalize(signed))).value;
}

/**
 * 生成一条完整的合法链夹具。
 * 层级：root -> 区域值班 -> 船载终端 -> 末端命令（目标 buoy）。
 *
 * @param {object} [opts]
 * @param {number} [opts.now]
 * @param {number} [opts.windowSec=3600]
 * @param {string} [opts.buoy='BUOY-A01']
 * @param {number} [opts.amount=12]
 * @param {Array<{allowedBuoys?:string[], sampleLimit?:number, notBefore?:number, notAfter?:number}>} [opts.override]
 *        按跳覆盖约束，用于构造“越权/放宽/篡改”夹具
 */
export async function buildChain(opts = {}) {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const windowSec = opts.windowSec ?? 3600;
  const buoy = opts.buoy ?? 'BUOY-A01';
  const amount = opts.amount ?? 12;

  const root = await generateP256('root');
  const regional = await generateP256('regional-duty');
  const vessel = await generateP256('vessel-terminal');

  // 默认逐级收紧
  const levels = [
    {
      signer: root,
      subject: regional.publicKey,
      allowedBuoys: ['BUOY-A01', 'BUOY-A02', 'BUOY-B07'],
      sampleLimit: 100,
      notBefore: now - 60,
      notAfter: now + windowSec,
    },
    {
      signer: regional,
      subject: vessel.publicKey,
      allowedBuoys: ['BUOY-A01', 'BUOY-A02'],
      sampleLimit: 50,
      notBefore: now - 30,
      notAfter: now + Math.floor(windowSec / 2),
    },
    {
      signer: vessel,
      subject: vessel.publicKey, // 末端命令主体即执行者自身
      kind: 'command',
      allowedBuoys: ['BUOY-A01'],
      sampleLimit: 20,
      notBefore: now - 10,
      notAfter: now + Math.floor(windowSec / 4),
      command: { buoy, amount },
    },
  ];

  (opts.override ?? []).forEach((ov, i) => {
    if (!ov) return;
    Object.assign(levels[i], ov);
  });

  const entries = [];
  for (let i = 0; i < levels.length; i++) {
    const lv = levels[i];
    const kind = lv.kind ?? 'delegation';
    entries.push(
      await issueEnvelope({
        signerKey: lv.signer.keyPair.privateKey,
        signerJwk: lv.signer.publicKey,
        subjectJwk: lv.subject,
        kind,
        notBefore: lv.notBefore,
        notAfter: lv.notAfter,
        allowedBuoys: lv.allowedBuoys,
        sampleLimit: lv.sampleLimit,
        command: lv.command,
      })
    );
  }

  return {
    rootJwk: root.publicKey,
    rootKey: root.keyPair.privateKey,
    keys: { root, regional, vessel },
    entries,
    now,
  };
}

/**
 * 对已签发对象做“字节级改写”而保持签名不变，用于篡改测试。
 */
export function tamperEnvelope(envelope, mutate) {
  const copy = structuredClone(envelope);
  mutate(copy);
  return copy;
}
