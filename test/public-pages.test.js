'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtemp, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join, resolve, sep } = require('node:path');
const net = require('node:net');

test('real server boots with isolated database, serves release policies, and protects entitlements', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'agronom-server-test-'));
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const server = spawn(process.execPath, [join(__dirname, '..', 'index.js')], {
    cwd: directory, stdio: 'ignore', env: { ...process.env, PORT: String(port),
      NODE_ENV: 'test', JWT_SECRET: 'isolated-test-secret',
      GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: '', GOOGLE_APPLICATION_CREDENTIALS: '', DB_PATH: join(directory, 'persistent', 'users.db') },
  });
  t.after(async () => {
    if (server.exitCode === null) {
      const exited = new Promise(resolve => server.once('exit', resolve));
      server.kill(); await exited;
    }
    const prefix = resolve(tmpdir()) + sep + 'agronom-server-test-';
    if (!resolve(directory).startsWith(prefix)) throw new Error('Unsafe temporary directory');
    await rm(directory, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${port}`;
  let started = false;
  for (let i = 0; i < 100; i++) {
    try { started = (await fetch(base)).ok; if (started) break; } catch (_) { /* Startup not finished. */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(started, true, 'Auth server must start even when billing credentials are absent');
  for (const page of ['account-deletion', 'privacy-policy', 'terms-of-use']) {
    const response = await fetch(`${base}/${page}`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /text\/html/);
    const html = await response.text();
    assert.match(html, /agronomonlajn@gmail\.com/);
    assert.match(html, /lang="uk"/);
  }
  const status = await (await fetch(`${base}/billing/status`)).json();
  assert.equal(status.billingReady, false);
  assert.equal(status.productId, 'agronom_premium_monthly');
  assert.equal(status.identityProvider, 'firebase');
  assert.equal(status.billingApiVersion, 2);
  assert.equal(status.firebaseProjectId, 'agronomonline-68820');
  assert.equal((await fetch(`${base}/billing/entitlement`)).status, 401);
});
