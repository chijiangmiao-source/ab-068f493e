'use strict';
// 规范 JSON（JCS / RFC 8785 子集）序列化与严格解析。
// - 对象键按 UTF-16 码元升序排列
// - 拒绝 NaN / Infinity（非有限数）
// - 拒绝超出 JS 安全整数范围的整数（越界整数 / 不安全整数）
// - 数字按 JCS 的 ECMAScript Number-to-string 最短往返形式输出
// - 严格解析依赖 strictParse 对重复键等问题的前置检查

const INTEGER_RE = /^-?(0|[1-9][0-9]*)$/;

/**
 * 判断一个已解析的数字是否为“整数形态”。
 * JSON 中 1.0 解析后与 1 无法区分，统一按整数处理并做安全范围检查。
 */
function isIntegerValue(n) {
  return Number.isSafeInteger(n);
}

/**
 * JCS 风格的数字最短序列化（与 ECMAScript Number.prototype.toString 一致）。
 * Node 的 String(number) 即使用最短往返表示，符合 RFC 8785 要求。
 */
export function canonicalNumber(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) {
    throw new TypeError('non-finite number');
  }
  return String(n);
}

/**
 * 将已解析的 JS 值序列化为规范 JSON 字节（Uint8Array）。
 * 调用前应通过 strictParse 解析，保证不存在重复键。
 */
export function canonicalize(value) {
  return new TextEncoder().encode(canonicalizeString(value));
}

export function canonicalizeString(value) {
  return writeValue(value, '$');
}

function writeValue(value, path) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw jce(path, 'non-finite number (NaN/Infinity is not valid JSON)');
    }
    // 注：不安全“整数”词法在 strictParse 阶段按原文拒绝；
    // 此处严格遵循 JCS 最短往返序列化，避免对 1.5e21 这类非整数形态误报。
    return String(value);
  }
  if (t === 'string') return quoteString(value, path);
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const parts = value.map((v, i) => writeValue(v, `${path}[${i}]`));
    return '[' + parts.join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return '{}';
    keys.sort(utf16Compare);
    const parts = keys.map((k) => {
      const childPath = `${path}.${k}`;
      return quoteString(k, childPath) + ':' + writeValue(value[k], childPath);
    });
    return '{' + parts.join(',') + '}';
  }
  // undefined / function / bigint / symbol
  throw jce(path, `value of unsupported type ${t}`);
}

function quoteString(s, path) {
  if (typeof s !== 'string') throw jce(path, 'expected string key');
  return JSON.stringify(s);
}

// RFC 8785 §3.2.3：按 UTF-16 码元升序排序对象键
function utf16Compare(a, b) {
  const la = a.length;
  const lb = b.length;
  const n = Math.min(la, lb);
  for (let i = 0; i < n; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
  return la - lb;
}

function jce(path, message) {
  const err = new Error(`at ${path}: ${message}`);
  err.path = path;
  err.code = 'CANONICAL_ERROR';
  return err;
}

export class JsonParseError extends Error {
  constructor(message, { line = 1, column = 1, position = 0, path = '$' } = {}) {
    super(`at ${path} (line ${line} col ${column}): ${message}`);
    this.name = 'JsonParseError';
    this.line = line;
    this.column = column;
  }
}

/**
 * 严格 JSON 解析：
 *  - 拒绝重复对象键（报告首个重复键的行列与 JSON Pointer）
 *  - 拒绝非有限数字（NaN/Infinity 在标准 JSON.parse 中本就拒绝）
 *  - 拒绝不安全范围的整数（|n| > 2^53-1）
 *  - 拒绝越界数值（超出 Number 范围变为 Infinity）
 *  - 拒绝规范序列化会改变键序的输入（对象键序不规范）
 *
 * 返回 { value, issues }；解析本身失败直接 throw JsonParseError。
 */
export function strictParse(text) {
  if (typeof text !== 'string') text = new TextDecoder().decode(text);

  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    const loc = extractV8Location(e.message, text);
    throw new JsonParseError(
      e.message.replace(/^.*JSON\.parse: /, '').replace(/^in JSON.*$/, 'invalid JSON syntax'),
      loc
    );
  }

  // JSON.parse 已拒绝注释、尾逗号、单引号、NaN/Infinity 等。
  // 重复键、键序、不安全整数、越界数值需要自行扫描原始文本：
  const lint = lintRawJson(text);
  if (lint.duplicateKey) {
    const d = lint.duplicateKey;
    throw new JsonParseError(`duplicate object key ${JSON.stringify(d.key)}`, {
      line: d.line,
      column: d.column,
      path: d.path,
    });
  }
  if (lint.unsafeInteger) {
    const z = lint.unsafeInteger;
    throw new JsonParseError(
      `integer ${z.raw} is outside the safe integer range [-(2^53-1), 2^53-1]`,
      { line: z.line, column: z.column, path: z.path }
    );
  }
  if (lint.nonFinite) {
    const z = lint.nonFinite;
    throw new JsonParseError(`non-finite or out-of-range number ${z.raw}`, {
      line: z.line,
      column: z.column,
      path: z.path,
    });
  }
  if (lint.keyOrderIssue) {
    const k = lint.keyOrderIssue;
    throw new JsonParseError(
      `object keys are not in canonical order: ${JSON.stringify(k.previous)} must come after ${JSON.stringify(k.key)}`,
      { line: k.line, column: k.column, path: k.path }
    );
  }
  return { value };
}

/**
 * 一次性扫描原始 JSON 文本，做语法之外的结构检查。
 * 返回 { duplicateKey?, unsafeInteger?, nonFinite?, keyOrderIssue? }
 */
function lintRawJson(text) {
  const p = new Scanner(text);
  const result = {};
  scanValue(p, [], result, true);
  p.ws();
  if (!result.duplicateKey && p.i < text.length) {
    const { line, column } = p.loc();
    throw new JsonParseError('unexpected trailing content after JSON value', {
      line,
      column,
    });
  }
  return result;
}

const ESCAPED = {
  '"': '"',
  '\\': '\\',
  '/': '/',
  b: '\b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t',
};

function scanValue(p, path, result, checkOrder) {
  p.ws();
  const c = p.peek();
  if (c === '{') return scanObject(p, path, result);
  if (c === '[') return scanArray(p, path, result);
  if (c === '"') return scanString(p);
  return scanLiteral(p, path, result);
}

function scanObject(p, path, result) {
  p.next(); // {
  p.ws();
  const seen = new Map(); // key -> {line,column}
  const orderedKeys = [];
  if (p.peek() === '}') {
    p.next();
    return;
  }
  for (;;) {
    p.ws();
    if (p.peek() !== '"') {
      const { line, column } = p.loc();
      throw new JsonParseError('expected string key in object', { line, column });
    }
    const keyStart = p.loc();
    const key = scanString(p);
    p.ws();
    if (p.next() !== ':') {
      const { line, column } = p.loc();
      throw new JsonParseError("expected ':' after object key", { line, column });
    }
    if (seen.has(key) && !result.duplicateKey) {
      result.duplicateKey = {
        key,
        line: keyStart.line,
        column: keyStart.column,
        path: pointer(path, key),
      };
    }
    seen.set(key, keyStart);
    orderedKeys.push({ key, ...keyStart });

    const childPath = [...path, key];
    scanValue(p, childPath, result, false);
    p.ws();
    const c = p.next();
    if (c === ',') continue;
    if (c === '}') break;
    const { line, column } = p.loc();
    throw new JsonParseError("expected ',' or '}' in object", { line, column });
  }

  // 键序规范检查：键必须已按 UTF-16 码元升序排列
  if (!result.keyOrderIssue) {
    for (let i = 1; i < orderedKeys.length; i++) {
      const prev = orderedKeys[i - 1];
      const cur = orderedKeys[i];
      if (utf16Compare(prev.key, cur.key) > 0) {
        result.keyOrderIssue = {
          key: cur.key,
          previous: prev.key,
          line: cur.line,
          column: cur.column,
          path: pointer(path, cur.key),
        };
        break;
      }
    }
  }
}

function scanArray(p, path, result) {
  p.next(); // [
  p.ws();
  if (p.peek() === ']') {
    p.next();
    return;
  }
  let idx = 0;
  for (;;) {
    scanValue(p, [...path, idx], result, false);
    idx++;
    p.ws();
    const c = p.next();
    if (c === ',') continue;
    if (c === ']') break;
    const { line, column } = p.loc();
    throw new JsonParseError("expected ',' or ']' in array", { line, column });
  }
}

function scanString(p) {
  p.next(); // opening quote
  let out = '';
  for (;;) {
    const c = p.next();
    if (c === undefined) {
      const { line, column } = p.loc();
      throw new JsonParseError('unterminated string', { line, column });
    }
    if (c === '"') return out;
    if (c === '\\') {
      const e = p.next();
      if (e === 'u') {
        const hex = p.text.slice(p.i, p.i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          const { line, column } = p.loc();
          throw new JsonParseError('invalid unicode escape', { line, column });
        }
        p.i += 4;
        out += String.fromCharCode(parseInt(hex, 16));
      } else if (e in ESCAPED) {
        out += ESCAPED[e];
      } else {
        const { line, column } = p.loc();
        throw new JsonParseError(`invalid escape \\${e}`, { line, column });
      }
    } else {
      out += c;
    }
  }
}

function scanLiteral(p, path, result) {
  const start = p.i;
  const { line, column } = p.loc();
  const c = p.peek();
  if (c === 't') {
    if (p.text.startsWith('true', p.i)) {
      p.i += 4;
      return true;
    }
  } else if (c === 'f') {
    if (p.text.startsWith('false', p.i)) {
      p.i += 5;
      return false;
    }
  } else if (c === 'n') {
    if (p.text.startsWith('null', p.i)) {
      p.i += 4;
      return null;
    }
  } else if (c === '-' || (c >= '0' && c <= '9')) {
    return scanNumber(p, path, result, start, line, column);
  }
  throw new JsonParseError('unexpected token', { line, column });
}

function scanNumber(p, path, result, start, line, column) {
  // 标准 JSON 数字语法；另记录原始文本用于整数安全范围检查
  const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
    p.text.slice(p.i)
  );
  if (!m) {
    throw new JsonParseError('invalid number', { line, column });
  }
  const raw = m[0];
  p.i += raw.length;
  const n = Number(raw);
  const ptr = pointer(path);
  if (!Number.isFinite(n)) {
    if (!result.nonFinite) {
      result.nonFinite = { raw, line, column, path: ptr };
    }
  } else if (INTEGER_RE.test(raw) && !Number.isSafeInteger(n)) {
    if (!result.unsafeInteger) {
      result.unsafeInteger = { raw, line, column, path: ptr };
    }
  }
  return n;
}

function pointer(path, extra) {
  const parts = [...path];
  if (extra !== undefined) parts.push(extra);
  if (parts.length === 0) return '$';
  return (
    '$' +
    parts
      .map((seg) =>
        typeof seg === 'number'
          ? `[${seg}]`
          : '.' + String(seg).replace(/\./g, '\\.')
      )
      .join('')
  );
}

// V8 的 JSON.parse 错误形如 "... at position 42"，转换为行列号。
function extractV8Location(message, text) {
  const m = /position\s+(\d+)/.exec(message);
  if (!m) return { line: 1, column: 1 };
  const pos = Math.min(Number(m[1]), Math.max(text.length - 1, 0));
  let line = 1;
  let column = 1;
  for (let i = 0; i < pos; i++) {
    if (text[i] === '\n') {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  return { line, column };
}

class Scanner {
  constructor(text) {
    this.text = text;
    this.i = 0;
    this.line = 1;
    this.col = 1;
  }  peek() {
    return this.text[this.i];
  }
  next() {
    const c = this.text[this.i++];
    if (c === '\n') {
      this.line++;
      this.col = 1;
    } else if (c !== undefined) {
      this.col++;
    }
    return c;
  }
  ws() {
    while (this.i < this.text.length) {
      const c = this.text[this.i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') this.next();
      else break;
    }
  }
  loc() {
    return { line: this.line, column: this.col };
  }
}
