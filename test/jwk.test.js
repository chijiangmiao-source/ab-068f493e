'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { validatePublicJwk, jwkThumbprint, generateP256 } from '../src/core/jwk.js';

test('jwk: 合法 P-256 JWK 通过校验', () => {
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'kbjH3Jj0O-348GQ1Y3Ux7y4mZ7d0W5Q9A2r1XwS227Q',
    y: 'kbjH3Jj0O-348GQ1Y3Ux7y4mZ7d0W5Q9A2r1XwS227Q',
  };
  const clean = validatePublicJwk(jwk);
  assert.deepEqual(clean, jwk);
});

test('jwk: 错误曲线/私钥材料/坐标长度被拒绝', () => {
  assert.throws(() => validatePublicJwk({ kty: 'EC', crv: 'P-384', x: 'x', y: 'y' }), /P-256/);
  assert.throws(
    () => validatePublicJwk({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'secret' }),
    /unexpected JWK member "d"/
  );
  const badLen = 'AAAA';
  assert.throws(
    () => validatePublicJwk({ kty: 'EC', crv: 'P-256', x: badLen, y: badLen }),
    /32 bytes/
  );
});

test('jwk: thumbprint 稳定且确定（SHA-256 -> 43 字符 base64url）', async () => {
  const { publicKey } = await generateP256();
  const t1 = await jwkThumbprint(publicKey);
  const t2 = await jwkThumbprint(publicKey);
  assert.equal(t1, t2);
  assert.equal(t1.length, 43); // base64url(sha256)
});
