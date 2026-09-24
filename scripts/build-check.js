'use strict';
// 页面/代码构建检查（无第三方依赖）：
//  1. 对所有 JS 文件做语法检查（node --check）
//  2. 校验 index.html 引用的静态资源都存在
//  3. 校验核心 ES Module 可被导入
import { execFileSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

const DIRS = ['src', 'public', 'test', 'bin', 'scripts'];

async function walk(dir, out = []) {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) await walk(p, out);
    else if (e.name.endsWith('.js')) out.push(p);
  }
  return out;
}

let failed = 0;
const files = [];
for (const d of DIRS) files.push(...(await walk(path.join(ROOT, d))));

for (const f of files) {
  try {
    execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' });
    console.log(`  syntax OK  ${path.relative(ROOT, f)}`);
  } catch (e) {
    failed++;
    console.error(`  syntax FAIL ${path.relative(ROOT, f)}\n${e.stderr?.toString() || e.message}`);
  }
}

// index.html 资源引用检查
const html = await fs.readFile(path.join(ROOT, 'public', 'index.html'), 'utf8');
const refs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1]);
for (const ref of refs) {
  if (ref.startsWith('http')) continue;
  const file = path.join(ROOT, 'public', ref.replace(/^\//, ''));
  try {
    await fs.access(file);
    console.log(`  asset OK   ${ref}`);
  } catch {
    failed++;
    console.error(`  asset MISSING ${ref}`);
  }
}

// 模块导入检查
try {
  await import('../src/core/verify.js');
  await import('../src/server.js');
  console.log('  module import OK  src/core/verify.js, src/server.js');
} catch (e) {
  failed++;
  console.error(`  module import FAIL: ${e.message}`);
}

if (failed > 0) {
  console.error(`build-check: ${failed} 个检查失败`);
  process.exit(1);
}
console.log(`build-check: 全部通过（${files.length} 个 JS 文件，${refs.length} 个页面引用）`);
