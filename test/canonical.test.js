'use strict';

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalize,
  canonicalizeString,
  strictParse,
  JsonParseError,
} from '../src/core/canonical.js';

test('canonical: 对象键按 UTF-16 码元排序，无空白', () => {
  const out = canonicalizeString({ b: 1, a: 2, c: 3 });
  assert.equal(out, '{"a":2,"b":1,"c":3}');
});

test('canonical: 嵌套对象与数组稳定序列化', () => {
  const v = { z: [3, { y: 1, x: 2 }], a: '好' };
  assert.equal(canonicalizeString(v), '{"a":"好","z":[3,{"x":2,"y":1}]}');
});

test('canonical: 数字最短往返形式', () => {
  assert.equal(canonicalizeString(0.0000001), '1e-7');
  assert.equal(canonicalizeString(1.5e21), '1.5e+21');
  assert.equal(canonicalizeString(-0), '0');
  assert.equal(canonicalizeString(100), '100');
});

test('strict: 重复键被拒绝并定位', () => {
  assert.throws(
    () => strictParse('{"a":1,"b":2,"a":3}'),
    (e) => {
      assert.ok(e instanceof JsonParseError);
      assert.match(e.message, /duplicate object key "a"/);
      assert.equal(e.line, 1);
      assert.ok(e.column > 0);
      return true;
    }
  );
});

test('strict: 嵌套重复键给出路径', () => {
  assert.throws(
    () => strictParse('{"o":{"x":1,"x":2}}'),
    /duplicate object key "x"/
  );
});

test('strict: 键序不规范被拒绝', () => {
  assert.throws(
    () => strictParse('{"b":1,"a":2}'),
    /keys are not in canonical order/
  );
});

test('strict: 不安全整数 9007199254740993 被拒绝', () => {
  assert.throws(
    () => strictParse('9007199254740993'),
    /outside the safe integer range/
  );
  assert.throws(
    () => strictParse('{"sampleLimit":9007199254740993}'),
    /outside the safe integer range/
  );
});

test('strict: 越界数值 1e999 被拒绝（非有限）', () => {
  assert.throws(
    () => strictParse('1e999'),
    /non-finite or out-of-range/
  );
});

test('strict: NaN/Infinity 不是合法 JSON', () => {
  assert.throws(() => strictParse('NaN'), JsonParseError);
  assert.throws(() => strictParse('Infinity'), JsonParseError);
});

test('strict: 尾随内容与标准 JSON 语法错误被拒绝', () => {
  assert.throws(() => strictParse('{} {}'), JsonParseError);
  assert.throws(() => strictParse('{"a":}'), JsonParseError);
  assert.throws(() => strictParse('{"a":1,}'), JsonParseError);
});

test('strict: 合法规范文本解析成功且可重新规范化', () => {
  const text = '{"a":[1,2,3],"b":"x"}';
  const { value } = strictParse(text);
  assert.deepEqual(value, { a: [1, 2, 3], b: 'x' });
  assert.deepEqual(Array.from(canonicalize(value)), Array.from(new TextEncoder().encode(text)));
});
