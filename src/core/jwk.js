'use strict';
// P-256 JWK（RFC 7517 / RFC 7518）处理：
// - 校验 crv=P-256、kty=EC、坐标为 base64url 的 32 字节
// - 使用 WebCrypto 导入公钥（仅允许公钥出现在签发者/主体字段）
// - 计算 RFC 7638 JWK Thumbprint（SHA-256）作为密钥身份

import { canonicalize } from './canonical.js';

export class JwkError extends Error {
  constructor(message, path) {
    super(path ? `${path}: ${message}` : message);
    this.name = 'JwkError';
    this.path = path;
  }
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function b64urlDecode(s, path) {
  if (typeof s !== 'string' || !B64URL_RE.test(s)) {
    throw new JwkError('expected base64url string', path);
  }
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * 校验并规范化为一个仅含必需成员的 P-256 公钥 JWK。
 * 拒绝私钥材料（d）、未知曲线、错误坐标长度、多余/缺失字段。
 */
export function validatePublicJwk(jwk, path = '$.issuer') {
  if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) {
    throw new JwkError('JWK must be a JSON object', path);
  }
  const allowed = new Set(['kty', 'crv', 'x', 'y', 'kid']);
  for (const k of Object.keys(jwk)) {
    if (!allowed.has(k)) {
      throw new JwkError(`unexpected JWK member ${JSON.stringify(k)}`, `${path}.${k}`);
    }
  }
  if (jwk.kty !== 'EC') throw new JwkError('kty must be "EC"', `${path}.kty`);
  if (jwk.crv !== 'P-256') throw new JwkError('crv must be "P-256"', `${path}.crv`);
  if (typeof jwk.x !== 'string') throw new JwkError('x must be a string', `${path}.x`);
  if (typeof jwk.y !== 'string') throw new JwkError('y must be a string', `${path}.y`);
  const x = b64urlDecode(jwk.x, `${path}.x`);
  const y = b64urlDecode(jwk.y, `${path}.y`);
  if (x.length !== 32) {
    throw new JwkError(`P-256 x coordinate must be 32 bytes (got ${x.length})`, `${path}.x`);
  }
  if (y.length !== 32) {
    throw new JwkError(`P-256 y coordinate must be 32 bytes (got ${y.length})`, `${path}.y`);
  }
  if ('kid' in jwk && (typeof jwk.kid !== 'string' || jwk.kid.length === 0)) {
    throw new JwkError('kid must be a non-empty string when present', `${path}.kid`);
  }
  // 按规范键序（crv < kid? < kty < x < y）输出
  return toCanonicalJwk(jwk);
}

function toCanonicalJwk(jwk) {
  const clean = { crv: 'P-256' };
  if (jwk.kid) clean.kid = jwk.kid;
  clean.kty = 'EC';
  clean.x = jwk.x;
  clean.y = jwk.y;
  return clean;
}

export async function importPublicJwk(jwk) {
  // WebCrypto 不接受 kid
  const { kid: _ignored, ...minimal } = jwk;
  return crypto.subtle.importKey(
    'jwk',
    { ...minimal, ext: true, key_ops: ['verify'] },
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

/**
 * RFC 7638 JWK Thumbprint：canonical JSON of {crv,kty,x,y}（键序由 canonicalize 保证）。
 */
export async function jwkThumbprint(jwk) {
  const tp = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const digest = await crypto.subtle.digest('SHA-256', canonicalize(tp));
  return toBase64Url(new Uint8Array(digest));
}

/**
 * 公钥结构相等（用于“签发者必须等于前一主体”的逐跳链接检查）。
 */
export function samePublicJwk(a, b) {
  return a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}

export function toBase64Url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * 生成一把新的 P-256 密钥（演示/测试签发用）。
 */
export async function generateP256(kid) {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const pubJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const privJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  // 按规范键序（crv < kid < kty < x < y）构造，保证 JSON.stringify 即为规范字节
  const publicKey = kid
    ? { crv: 'P-256', kid, kty: 'EC', x: pubJwk.x, y: pubJwk.y }
    : { crv: 'P-256', kty: 'EC', x: pubJwk.x, y: pubJwk.y };
  return {
    publicKey,
    privateJwk: privJwk,
    keyPair: pair,
  };
}

export async function signRaw(privateKey, canonicalBytes) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    canonicalBytes
  );
  // WebCrypto 产出 IEEE P1363 r||s 定长签名，直接 base64url
  return toBase64Url(new Uint8Array(sig));
}

export async function verifyRaw(publicKey, canonicalBytes, signatureB64) {
  let sig;
  try {
    sig = fromBase64Url(signatureB64);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sig,
      canonicalBytes
    );
  } catch {
    return false;
  }
}
