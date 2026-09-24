'use strict';
// 岸站 HTTP 服务：
//  GET  /                 值班员静态页面
//  GET  /healthz          健康响应（200 {"status":"ok",...}）
//  POST /api/verify       验签：{root:<jwk 文本或对象>, chain:<文本或数组>}
//                         有效证据写入 data/evidence/；拒绝结果只写 data/denied/，
//                         绝不会覆盖上一份有效证据。
// 静态资源：/public、/src（供页面直接以 ES Module 复用同一套核心代码）

import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

import { verifyChain, parseChainEntries, parseRootJwk } from './core/verify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const SRC_DIR = path.join(ROOT_DIR, 'src');
const DATA_DIR = path.join(ROOT_DIR, 'data');
const EVIDENCE_DIR = path.join(DATA_DIR, 'evidence');
const DENIED_DIR = path.join(DATA_DIR, 'denied');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.map': 'application/json; charset=utf-8',
};

async function ensureDirs() {
  await fs.mkdir(EVIDENCE_DIR, { recursive: true });
  await fs.mkdir(DENIED_DIR, { recursive: true });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

async function readBody(req, limit = 1024 * 1024) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      const err = new Error('payload too large');
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function handleVerify(req, res) {
  let parsed;
  try {
    const raw = await readBody(req);
    parsed = raw ? JSON.parse(raw) : {};
  } catch (e) {
    return sendJson(res, e.statusCode || 400, {
      status: 'deny',
      error: { code: 'BAD_REQUEST', message: `请求体不是合法 JSON：${e.message}` },
    });
  }

  let rootJwk;
  let entries;
  try {
    const rootInput =
      typeof parsed.root === 'string' ? parsed.root : JSON.stringify(parsed.root ?? {});
    rootJwk = parseRootJwk(rootInput);
    const chainInput =
      typeof parsed.chain === 'string' ? parsed.chain : JSON.stringify(parsed.chain ?? []);
    entries = parseChainEntries(chainInput);
  } catch (e) {
    return sendJson(res, 200, {
      status: 'deny',
      error: {
        code: e.code || 'BAD_REQUEST',
        message: e.message,
        hop: e.hop,
        field: e.field,
        path: e.path,
        objectIndex: e.objectIndex,
        line: e.line,
        column: e.column,
      },
    });
  }

  const result = await verifyChain({ root: rootJwk, entries, now: parsed.now });

  // 证据隔离：只有 allow 才写 evidence/；deny 写 denied/，绝不覆盖有效证据。
  try {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    if (result.status === 'allow') {
      const id = crypto.createHash('sha256').update(JSON.stringify(result.hops)).digest('hex').slice(0, 16);
      await fs.writeFile(
        path.join(EVIDENCE_DIR, `evidence-${stamp}-${id}.json`),
        JSON.stringify({ savedAt: new Date().toISOString(), result }, null, 2)
      );
    } else {
      await fs.writeFile(
        path.join(DENIED_DIR, `denied-${stamp}.json`),
        JSON.stringify({ savedAt: new Date().toISOString(), result }, null, 2)
      );
    }
  } catch {
    // 证据落盘失败不影响验签结论本身
  }

  return sendJson(res, 200, result);
}

async function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath);
  if (rel === '/') rel = '/index.html';

  // 明确的静态根映射
  let file;
  if (rel.startsWith('/src/')) {
    file = path.normalize(path.join(SRC_DIR, rel.slice('/src/'.length)));
    if (!file.startsWith(SRC_DIR + path.sep)) return send404(res);
  } else {
    file = path.normalize(path.join(PUBLIC_DIR, rel));
    if (!file.startsWith(PUBLIC_DIR + path.sep)) return send404(res);
  }

  let data;
  try {
    data = await fs.readFile(file);
  } catch {
    return send404(res);
  }
  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, {
    'content-type': MIME[ext] || 'application/octet-stream',
    'content-length': data.length,
  });
  res.end(data);
}

function send404(res) {
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('not found');
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (req.method === 'GET' && (url.pathname === '/healthz' || url.pathname === '/health')) {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'buoy-dcid-chain',
        time: new Date().toISOString(),
        port: PORT,
      });
    }
    if (req.method === 'POST' && url.pathname === '/api/verify') {
      return await handleVerify(req, res);
    }
    if (req.method === 'GET') {
      return await serveStatic(req, res, url.pathname);
    }
    return sendJson(res, 405, { status: 'error', message: 'method not allowed' });
  } catch (e) {
    return sendJson(res, 500, { status: 'error', message: e.message });
  }
});

export function startServer(port = PORT, host = HOST) {
  return new Promise((resolve) => {
    ensureDirs().then(() => {
      server.listen(port, host, () => resolve({ server, port, host }));
    });
  });
}

// 直接执行时启动（被 verify 子进程 import 时不自动 listen）
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().then(({ port, host }) => {
    console.log(`[buoy-dcid-chain] 岸站服务已启动: http://${host}:${port}`);
    console.log(`[buoy-dcid-chain] 健康检查: http://${host}:${port}/healthz`);
  });
}
