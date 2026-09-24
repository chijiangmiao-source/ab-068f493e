'use strict';
// 离线受限委托链验签引擎。
//
// 每份对象（委托 / 末端命令）为一个 JSON 信封，字段：
//   allowedBuoys : string[]              允许浮标（非空、唯一）
//   command?     : { amount:int, buoy:string }  仅末端命令携带
//   issuer       : P-256 公钥 JWK        签发者
//   kind         : "delegation" | "command"
//   notBefore    : unix 秒（安全整数）    有效期起
//   notAfter     : unix 秒（安全整数）    有效期止
//   sampleLimit  : int（>=1）            采样上限
//   signature    : base64url(P-256 ECDSA-SHA256 over 规范 JSON(去 signature 的信封))
//   subject      : P-256 公钥 JWK        主体（下一跳签发者）
//
// 规则：
//  - 链首签发者必须等于粘贴的根公钥
//  - 每跳签名按同一套规范 JSON 字节（RFC 8785 风格 JCS）验证
//  - 后一跳签发者必须等于前一跳主体
//  - 时间窗只能收紧（notBefore 不减、notAfter 不增）
//  - 浮标集合只能收紧（子集）
//  - 采样上限只能收紧（不增）
//  - 末端浮标必须获得全部上游允许；采样量不得超过任一上游上限
//  - 任一检查失败：拒绝并定位到首个限制字段或签名失败跳

import { strictParse, canonicalize, JsonParseError } from './canonical.js';
import {
  validatePublicJwk,
  importPublicJwk,
  jwkThumbprint,
  samePublicJwk,
  fromBase64Url,
} from './jwk.js';

export class ChainError extends Error {
  constructor(code, message, loc = {}) {
    super(message);
    this.name = 'ChainError';
    this.code = code;
    Object.assign(this, loc); // { hop, field, path, objectIndex, line, column, ... }
  }
}

const ENVELOPE_KEYS = new Set([
  'allowedBuoys',
  'command',
  'issuer',
  'kind',
  'notAfter',
  'notBefore',
  'sampleLimit',
  'signature',
  'subject',
]);
const COMMAND_KEYS = new Set(['amount', 'buoy']);

function nowSeconds(now) {
  if (now === undefined) return Math.floor(Date.now() / 1000);
  return now;
}

/**
 * 解析值班员粘贴的链文本：
 *  - 规范 JSON 数组：[{"kind":"delegation",...}, ...]
 *  - 或 NDJSON：空白分隔的一串 JSON 对象
 * 每个对象独立做严格解析（重复键 / 非有限数 / 不安全整数 / 越界整数 / 键序）。
 */
export function parseChainEntries(text) {
  if (typeof text !== 'string') text = new TextDecoder().decode(text);
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    throw new ChainError('EMPTY_INPUT', '粘贴内容为空', { path: '$' });
  }

  if (trimmed.startsWith('[')) {
    // 逐元素切分后独立严格解析，确保 objectIndex / 行列定位到具体对象
    const chunks = splitTopLevelArrayValues(trimmed);
    const entries = [];
    for (const chunk of chunks) {
      let parsed;
      try {
        parsed = strictParse(chunk.text);
      } catch (e) {
        if (e instanceof JsonParseError) {
          const line = e.line + chunk.baseLine - 1;
          throw new ChainError('MALFORMED_JSON', e.message, {
            objectIndex: chunk.index,
            line,
            column: e.column,
            path: e.path,
          });
        }
        throw e;
      }
      const v = parsed.value;
      if (v === null || typeof v !== 'object' || Array.isArray(v)) {
        throw new ChainError('BAD_ENVELOPE', `第 ${chunk.index} 份对象不是 JSON 对象`, {
          objectIndex: chunk.index,
        });
      }
      entries.push(v);
    }
    if (entries.length === 0) {
      throw new ChainError('BAD_CHAIN', '链数组为空', { path: '$' });
    }
    return entries;
  }

  // NDJSON / 连续对象：用括号深度切分
  const chunks = splitTopLevelObjects(trimmed);
  const entries = [];
  chunks.forEach((chunk, idx) => {
    const { value } = parseStrict(chunk.text, idx);
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new ChainError('BAD_ENVELOPE', `第 ${idx} 份对象不是 JSON 对象`, {
        objectIndex: idx,
      });
    }
    entries.push(value);
  });
  if (entries.length === 0) {
    throw new ChainError('EMPTY_INPUT', '未在粘贴内容中找到任何 JSON 对象', {
      path: '$',
    });
  }
  return entries;
}

function parseStrict(text, objectIndex) {
  try {
    return strictParse(text);
  } catch (e) {
    if (e instanceof JsonParseError) {
      throw new ChainError('MALFORMED_JSON', e.message, {
        objectIndex,
        line: e.line,
        column: e.column,
        path: e.path,
      });
    }
    throw e;
  }
}

// 将顶层 JSON 数组文本切成逐元素片段（跳过字符串/嵌套括号），并记录起始行列
function splitTopLevelArrayValues(text) {
  const values = [];
  let depth = 0;
  let segStart = -1; // 当前元素的起点（[ 之后或 , 之后）
  let inStr = false;
  let esc = false;

  const pushSeg = (endExclusive) => {
    if (segStart < 0) return;
    const raw = text.slice(segStart, endExclusive);
    const lead = raw.match(/^\s*/)[0].length;
    const valueStart = segStart + lead;
    const prefix = text.slice(0, valueStart);
    const lines = prefix.split('\n');
    const baseLine = lines.length;
    const baseColumn = lines[lines.length - 1].length + 1;
    if (raw.trim().length > 0) {
      values.push({
        text: raw.trim(),
        index: values.length,
        baseLine,
        baseColumn,
      });
    }
    segStart = -1;
  };

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
    } else if (c === '[' || c === '{') {
      depth++;
      if (depth === 2 && c === '{') segStart = i; // 顶层元素对象开始
      if (depth === 1) segStart = i + 1; // [ 之后（可能是原始值元素）
    } else if (c === ']' || c === '}') {
      if (depth === 2 && c === '}') {
        pushSeg(i + 1);
      }
      if (depth === 1 && c === ']') {
        // 原始值元素或空数组收尾
        if (segStart >= 0) pushSeg(i);
        depth--;
        for (let j = i + 1; j < text.length; j++) {
          if (!/\s/.test(text[j])) {
            throw new ChainError('MALFORMED_JSON', '数组后存在尾随内容', { position: j });
          }
        }
        return values;
      }
      depth--;
    } else if (c === ',' && depth === 1) {
      pushSeg(i);
      segStart = i + 1;
    }
  }
  throw new ChainError('MALFORMED_JSON', 'JSON 数组未闭合', {});
}

// 按顶层大括号切分，正确跳过字符串与空白
function splitTopLevelObjects(text) {  const chunks = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
    } else if (c === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (c === '}') {
      depth--;
      if (depth === 0) chunks.push({ text: text.slice(start, i + 1) });
      if (depth < 0) {
        throw new ChainError('MALFORMED_JSON', '存在多余的 }', {
          position: i,
        });
      }
    } else if (depth === 0 && !/\s/.test(c)) {
      throw new ChainError(
        'MALFORMED_JSON',
        '多份对象时请使用 JSON 数组或以空白分隔的 JSON 对象',
        { position: i }
      );
    }
  }
  if (depth !== 0 || inStr) {
    throw new ChainError('MALFORMED_JSON', 'JSON 对象未闭合', {});
  }
  return chunks;
}

/**
 * 解析根公钥文本（单个 JWK 对象，严格规范要求同样适用）。
 */
export function parseRootJwk(text) {
  if (typeof text !== 'string') text = new TextDecoder().decode(text);
  const { value } = parseStrict(text.trim(), -1);
  return validatePublicJwk(value, '$.root');
}

function validateEnvelope(obj, hop) {
  const at = `entries[${hop}]`;
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new ChainError('BAD_ENVELOPE', '信封必须是 JSON 对象', { hop, path: at });
  }
  for (const k of Object.keys(obj)) {
    if (!ENVELOPE_KEYS.has(k)) {
      throw new ChainError(
        'BAD_ENVELOPE',
        `信封存在未知字段 ${JSON.stringify(k)}`,
        { hop, field: k, path: `${at}.${k}` }
      );
    }
  }
  const requireField = (k) => {
    if (!(k in obj)) {
      throw new ChainError('BAD_ENVELOPE', `信封缺少字段 ${k}`, {
        hop,
        field: k,
        path: `${at}.${k}`,
      });
    }
  };
  for (const k of ENVELOPE_KEYS) {
    if (k === 'command') continue;
    requireField(k);
  }

  if (obj.kind !== 'delegation' && obj.kind !== 'command') {
    throw new ChainError('BAD_ENVELOPE', `kind 必须是 delegation 或命令 command`, {
      hop,
      field: 'kind',
      path: `${at}.kind`,
    });
  }

  const issuer = validatePublicJwk(obj.issuer, `${at}.issuer`);
  const subject = validatePublicJwk(obj.subject, `${at}.subject`);

  const nbf = checkSafeInt(obj.notBefore, `${at}.notBefore`, hop, 'notBefore', {
    min: 0,
  });
  const exp = checkSafeInt(obj.notAfter, `${at}.notAfter`, hop, 'notAfter', {
    min: 0,
  });
  if (nbf >= exp) {
    throw new ChainError(
      'BAD_ENVELOPE',
      `有效期非法：notBefore(${nbf}) 必须小于 notAfter(${exp})`,
      { hop, field: 'notBefore', path: `${at}.notBefore` }
    );
  }

  if (!Array.isArray(obj.allowedBuoys) || obj.allowedBuoys.length === 0) {
    throw new ChainError('BAD_ENVELOPE', 'allowedBuoys 必须是非空数组', {
      hop,
      field: 'allowedBuoys',
      path: `${at}.allowedBuoys`,
    });
  }
  const buoys = [];
  const seen = new Set();
  obj.allowedBuoys.forEach((b, i) => {
    if (typeof b !== 'string' || b.length === 0) {
      throw new ChainError(
        'BAD_ENVELOPE',
        `allowedBuoys[${i}] 必须是非空字符串`,
        { hop, field: 'allowedBuoys', path: `${at}.allowedBuoys[${i}]` }
      );
    }
    if (seen.has(b)) {
      throw new ChainError('BAD_ENVELOPE', `allowedBuoys 出现重复浮标 ${b}`, {
        hop,
        field: 'allowedBuoys',
        path: `${at}.allowedBuoys[${i}]`,
      });
    }
    seen.add(b);
    buoys.push(b);
  });

  const limit = checkSafeInt(obj.sampleLimit, `${at}.sampleLimit`, hop, 'sampleLimit', {
    min: 1,
  });

  if (typeof obj.signature !== 'string' || obj.signature.length === 0) {
    throw new ChainError('BAD_ENVELOPE', 'signature 必须是非空 base64url 字符串', {
      hop,
      field: 'signature',
      path: `${at}.signature`,
    });
  }
  try {
    fromBase64Url(obj.signature);
  } catch {
    throw new ChainError('BAD_ENVELOPE', 'signature 不是合法 base64url', {
      hop,
      field: 'signature',
      path: `${at}.signature`,
    });
  }

  let command = null;
  if (obj.kind === 'command') {
    if (!obj.command || typeof obj.command !== 'object' || Array.isArray(obj.command)) {
      throw new ChainError('BAD_ENVELOPE', '末端命令必须携带 command 对象', {
        hop,
        field: 'command',
        path: `${at}.command`,
      });
    }
    for (const k of Object.keys(obj.command)) {
      if (!COMMAND_KEYS.has(k)) {
        throw new ChainError(
          'BAD_ENVELOPE',
          `command 存在未知字段 ${JSON.stringify(k)}`,
          { hop, field: `command.${k}`, path: `${at}.command.${k}` }
        );
      }
    }
    if (typeof obj.command.buoy !== 'string' || obj.command.buoy.length === 0) {
      throw new ChainError('BAD_ENVELOPE', 'command.buoy 必须是非空字符串', {
        hop,
        field: 'command.buoy',
        path: `${at}.command.buoy`,
      });
    }
    const amount = checkSafeInt(
      obj.command.amount,
      `${at}.command.amount`,
      hop,
      'command.amount',
      { min: 1 }
    );
    command = { buoy: obj.command.buoy, amount };
  } else if ('command' in obj) {
    throw new ChainError('BAD_ENVELOPE', '委托对象不得携带 command 字段', {
      hop,
      field: 'command',
      path: `${at}.command`,
    });
  }

  return {
    raw: obj,
    kind: obj.kind,
    issuer,
    subject,
    notBefore: nbf,
    notAfter: exp,
    allowedBuoys: buoys,
    sampleLimit: limit,
    signature: obj.signature,
    command,
  };
}

function checkSafeInt(v, path, hop, field, { min }) {
  if (typeof v !== 'number' || !Number.isFinite(v) || !Number.isSafeInteger(v)) {
    throw new ChainError(
      'BAD_ENVELOPE',
      `${field} 必须是安全范围内的整数`,
      { hop, field, path }
    );
  }
  if (v < min) {
    throw new ChainError('BAD_ENVELOPE', `${field} 必须 >= ${min}（实际 ${v}）`, {
      hop,
      field,
      path,
    });
  }
  return v;
}

/**
 * 验签入口。
 * @param {object} args
 * @param {object} args.root  根公钥 JWK（已校验或原始对象）
 * @param {Array}  args.entries 已解析的信封数组
 * @param {number} [args.now] 当前 unix 秒（便于测试）
 * @returns {Promise<object>} { status:'allow'|'deny', hops?, decision?, error? }
 */
export async function verifyChain({ root, entries, now } = {}) {
  const atNow = nowSeconds(now);
  try {
    const rootJwk = validatePublicJwk(root, '$.root');

    if (!Array.isArray(entries) || entries.length < 2) {
      throw new ChainError('BAD_CHAIN', '链至少包含 1 份委托和 1 份末端命令', {
        path: '$.entries',
      });
    }

    const envelopes = entries.map((e, i) => validateEnvelope(e, i));

    // 结构：前 n-1 份必须是 delegation，最后一份必须是 command
    envelopes.forEach((env, i) => {
      const last = i === envelopes.length - 1;
      if (last && env.kind !== 'command') {
        throw new ChainError('BAD_CHAIN', '链末端必须是 command', {
          hop: i,
          field: 'kind',
        });
      }
      if (!last && env.kind !== 'delegation') {
        throw new ChainError('BAD_CHAIN', 'command 只能位于链末端', {
          hop: i,
          field: 'kind',
        });
      }
    });

    // 根公钥信息
    const rootTp = await jwkThumbprint(rootJwk);

    // 预导入全部签发者公钥
    const issuerKeys = [];
    for (let i = 0; i < envelopes.length; i++) {
      try {
        issuerKeys.push(await importPublicJwk(envelopes[i].issuer));
      } catch (e) {
        throw new ChainError('BAD_SIGNATURE', `第 ${i} 跳签发者公钥无法导入: ${e.message}`, {
          hop: i,
          field: 'issuer',
        });
      }
    }

    // 逐跳：签名 -> 链接 -> 收紧 -> 当前时间窗
    const hops = [];
    let prev = null;
    for (let i = 0; i < envelopes.length; i++) {
      const env = envelopes[i];

      // 1) 链首签发者 == 根公钥
      if (i === 0) {
        if (!samePublicJwk(env.issuer, rootJwk)) {
          const issuerTp = await jwkThumbprint(env.issuer);
          throw new ChainError(
            'ROOT_MISMATCH',
            `链首签发者不等于根公钥（签发者 ${issuerTp.slice(0, 16)}…，根 ${rootTp.slice(0, 16)}…）`,
            { hop: 0, field: 'issuer', expected: rootTp, actual: issuerTp }
          );
        }
      } else {
        if (!samePublicJwk(env.issuer, prev.subject)) {
          const actualTp = await jwkThumbprint(env.issuer);
          const expectedTp = await jwkThumbprint(prev.subject);
          throw new ChainError(
            'CHAIN_LINK',
            `第 ${i} 跳签发者不是第 ${i - 1} 跳主体`,
            { hop: i, field: 'issuer', expected: expectedTp, actual: actualTp }
          );
        }
      }

      // 2) 规范字节签名验证（对去掉 signature 的信封做 JCS）
      const { bytes: payloadBytes, hexPreview } = signingPayload(env.raw);
      const payloadHash = await sha256B64Url(payloadBytes);
      const sigValid = await verifySignatureWith(issuerKeys[i], payloadBytes, env.signature);
      if (!sigValid) {
        throw new ChainError(
          'BAD_SIGNATURE',
          `第 ${i} 跳（${label(env)}）签名验证失败：签名与规范载荷不匹配`,
          {
            hop: i,
            field: 'signature',
            payloadHash,
            signerThumbprint: await jwkThumbprint(env.issuer),
          }
        );
      }

      // 3) 只允许收紧
      if (prev) {
        if (env.notBefore < prev.notBefore) {
          throw new ChainError(
            'POLICY_RELAXED',
            `时间窗被放宽：notBefore ${env.notBefore} 早于上游 ${prev.notBefore}（只许收紧）`,
            {
              hop: i,
              field: 'notBefore',
              upstream: prev.notBefore,
              value: env.notBefore,
            }
          );
        }
        if (env.notAfter > prev.notAfter) {
          throw new ChainError(
            'POLICY_RELAXED',
            `时间窗被放宽：notAfter ${env.notAfter} 晚于上游 ${prev.notAfter}（只许收紧）`,
            {
              hop: i,
              field: 'notAfter',
              upstream: prev.notAfter,
              value: env.notAfter,
            }
          );
        }
        const prevSet = new Set(prev.allowedBuoys);
        const added = env.allowedBuoys.find((b) => !prevSet.has(b));
        if (added !== undefined) {
          throw new ChainError(
            'POLICY_RELAXED',
            `浮标集合被放宽：${added} 不在上游允许集合中（只许收紧）`,
            {
              hop: i,
              field: 'allowedBuoys',
              value: added,
              upstream: prev.allowedBuoys,
            }
          );
        }
        if (env.sampleLimit > prev.sampleLimit) {
          throw new ChainError(
            'POLICY_RELAXED',
            `采样上限被放宽：${env.sampleLimit} 大于上游 ${prev.sampleLimit}（只许收紧）`,
            {
              hop: i,
              field: 'sampleLimit',
              upstream: prev.sampleLimit,
              value: env.sampleLimit,
            }
          );
        }
      }

      hops.push({
        index: i,
        kind: env.kind,
        issuerThumbprint: await jwkThumbprint(env.issuer),
        subjectThumbprint: await jwkThumbprint(env.subject),
        signature: env.signature,
        payloadHash,
        payloadLength: payloadBytes.length,
        payloadPreview: hexPreview,
        constraints: {
          notBefore: env.notBefore,
          notAfter: env.notAfter,
          allowedBuoys: [...env.allowedBuoys],
          sampleLimit: env.sampleLimit,
        },
      });
      prev = env;
    }

    // 4) 当前时间必须在有效窗口内；末端命令必须被每一跳允许
    const lastEnv = envelopes[envelopes.length - 1];
    const { buoy, amount } = lastEnv.command;

    for (let i = 0; i < envelopes.length; i++) {
      const env = envelopes[i];
      const blocker = (field, message, extra = {}) =>
        new ChainError('POLICY_DENIED', message, { hop: i, field, ...extra });

      if (atNow < env.notBefore) {
        throw blocker('notBefore', `第 ${i} 跳尚未生效（now=${atNow} < notBefore=${env.notBefore}）`, {
          now: atNow,
          value: env.notBefore,
        });
      }
      if (atNow > env.notAfter) {
        throw blocker('notAfter', `第 ${i} 跳已过期（now=${atNow} > notAfter=${env.notAfter}）`, {
          now: atNow,
          value: env.notAfter,
        });
      }
      if (!env.allowedBuoys.includes(buoy)) {
        throw blocker(
          i === envelopes.length - 1 ? 'command.buoy' : 'allowedBuoys',
          `末端浮标 ${buoy} 未获得第 ${i} 跳上游允许`,
          { value: buoy, allowedBuoys: env.allowedBuoys }
        );
      }
      if (amount > env.sampleLimit) {
        throw blocker(
          i === envelopes.length - 1 ? 'command.amount' : 'sampleLimit',
          `采样量 ${amount} 超过第 ${i} 跳上限 ${env.sampleLimit}`,
          { value: amount, upstream: env.sampleLimit }
        );
      }
    }

    // 有效链：收紧后的有效约束 = 全部跳约束的交集
    const effective = {
      notBefore: Math.max(...envelopes.map((e) => e.notBefore)),
      notAfter: Math.min(...envelopes.map((e) => e.notAfter)),
      allowedBuoys: intersectAll(envelopes.map((e) => e.allowedBuoys)),
      sampleLimit: Math.min(...envelopes.map((e) => e.sampleLimit)),
    };

    return {
      status: 'allow',
      verifiedAt: atNow,
      root: { thumbprint: rootTp, jwk: rootJwk },
      hops,
      effective,
      decision: {
        result: 'ALLOW',
        command: { buoy, amount },
        reason: `签名链全部有效，末端浮标 ${buoy} 获全部上游允许，采样量 ${amount} 不超任一上限`,
      },
    };
  } catch (e) {
    if (e instanceof ChainError) {
      const details = Object.fromEntries(
        Object.entries(e).filter(
          ([k]) => !['code', 'message', 'hop', 'field', 'path', 'objectIndex', 'line', 'column', 'name', 'stack'].includes(k)
        )
      );
      return {
        status: 'deny',
        verifiedAt: atNow,
        error: {
          code: e.code,
          message: e.message,
          hop: e.hop,
          field: e.field,
          path: e.path,
          objectIndex: e.objectIndex,
          line: e.line,
          column: e.column,
          ...details, // payloadHash / signerThumbprint / expected / actual / value 等
        },
      };
    }
    throw e;
  }
}

function label(env) {
  return env.kind === 'command' ? '末端命令' : '委托';
}

function intersectAll(lists) {
  let acc = new Set(lists[0]);
  for (const list of lists.slice(1)) {
    const s = new Set(list);
    acc = new Set([...acc].filter((x) => s.has(x)));
  }
  // 保持第一跳顺序
  return lists[0].filter((b) => acc.has(b));
}

/**
 * 构造签名载荷：去掉 signature 字段后做规范序列化。
 */
export function signingPayload(envelope) {
  const stripped = { ...envelope };
  delete stripped.signature;
  const bytes = canonicalize(stripped);
  return { bytes, hexPreview: previewBytes(bytes) };
}

function previewBytes(bytes) {
  const n = Math.min(bytes.length, 48);
  return Array.from(bytes.slice(0, n), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256B64Url(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  let bin = '';
  for (const b of new Uint8Array(digest)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function verifySignatureWith(cryptoKey, payloadBytes, signatureB64) {
  let sig;
  try {
    sig = fromBase64Url(signatureB64);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false; // P-256 r||s
  try {
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      sig,
      payloadBytes
    );
  } catch {
    return false;
  }
}
