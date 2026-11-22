'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const { entitlement, accountId, registerBilling } = require('../billing');
const future = () => new Date(Date.now() + 86400000).toISOString();
function receipt(state, extra = {}) {
  return { subscriptionState: `SUBSCRIPTION_STATE_${state}`,
    lineItems: [{ productId: 'agronom_premium_monthly', expiryTime: future() }], ...extra };
}
test('only paid, grace and canceled unexpired periods grant access', () => {
  for (const state of ['ACTIVE', 'IN_GRACE_PERIOD', 'CANCELED']) assert.equal(entitlement(receipt(state)).active, true);
  for (const state of ['PENDING', 'ON_HOLD', 'PAUSED', 'EXPIRED', 'PENDING_PURCHASE_CANCELED']) {
    assert.equal(entitlement(receipt(state)).active, false);
  }
  assert.equal(entitlement(receipt('ACTIVE', { lineItems: [{ productId: 'agronom_premium_monthly', expiryTime: '2000-01-01' }] })).active, false);
  assert.equal(entitlement(receipt('ACTIVE', { lineItems: [{ productId: 'different', expiryTime: future() }] })).active, false);
});
test('malformed billing credentials disable billing without breaking the auth app startup', async () => {
  const previous = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON;
  process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON = 'not-json';
  try {
    const routes = {};
    const app = { get: (path, ...handlers) => { routes[path] = handlers; }, post: () => {} };
    registerBilling(app, { dbGet: async () => null, dbAll: async () => [], dbRun: async () => ({ changes: 0 }), jwtSecret: 'test' });
    let status;
    await routes['/billing/status'][0]({}, { json: value => { status = value; } });
    assert.equal(status.billingReady, false);
  } finally {
    if (previous === undefined) delete process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON;
    else process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON = previous;
  }
});
test('verified restore is account-bound, revocation refreshes, and pending is never acknowledged', async t => {
  const db = new sqlite3.Database(':memory:');
  const dbGet = (sql, params) => new Promise((resolve, reject) => db.get(sql, params, (e, row) => e ? reject(e) : resolve(row)));
  const dbAll = (sql, params) => new Promise((resolve, reject) => db.all(sql, params, (e, rows) => e ? reject(e) : resolve(rows)));
  const dbRun = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, function(e) { e ? reject(e) : resolve({ changes: this.changes }); }));
  let state = 'ACTIVE', acknowledgements = 0;
  const googleClient = { async request(request) {
    if (request.url.endsWith('/subscriptions/agronom_premium_monthly')) return { data: {
      basePlans: [{ state: 'ACTIVE', autoRenewingBasePlanType: { billingPeriodDuration: 'P1M' } }],
    } };
    if (request.method === 'POST') { acknowledgements++; return { data: {} }; }
    return { data: receipt(state, {
      acknowledgementState: 'ACKNOWLEDGEMENT_STATE_PENDING',
      externalAccountIdentifiers: { obfuscatedExternalAccountId: accountId('1') },
    }) };
  } };
  const app = express(); app.use(express.json());
  const verifyFirebaseToken = async token => {
    const claims = jwt.verify(token, 'test-secret', { audience: 'agronomonline-68820', issuer: 'https://securetoken.google.com/agronomonline-68820' });
    if (!claims.uid) throw new Error('Firebase UID required');
    return claims;
  };
  registerBilling(app, { dbGet, dbRun, dbAll, verifyFirebaseToken, googleClient });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.on('listening', resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); await new Promise(resolve => db.close(resolve)); });
  const root = `http://127.0.0.1:${server.address().port}`;
  const request = (path, user = '1', body) => fetch(root + path, { method: body ? 'POST' : 'GET',
    headers: { Authorization: `Bearer ${jwt.sign({ uid: user }, 'test-secret', { audience: 'agronomonline-68820', issuer: 'https://securetoken.google.com/agronomonline-68820' })}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
  assert.equal((await fetch(root + '/billing/entitlement')).status, 401);
  const legacy = jwt.sign({ id: '1' }, 'test-secret');
  assert.equal((await fetch(root + '/billing/entitlement', { headers: { Authorization: `Bearer ${legacy}` } })).status, 401);
  const wrongProject = jwt.sign({ uid: '1' }, 'test-secret', { audience: 'different-project', issuer: 'https://securetoken.google.com/agronomonline-68820' });
  assert.equal((await fetch(root + '/billing/entitlement', { headers: { Authorization: `Bearer ${wrongProject}` } })).status, 401);
  const purchase = { productId: 'agronom_premium_monthly', purchaseToken: 'test-purchase-token' };
  let response = await request('/billing/google/verify', '1', purchase);
  assert.equal(response.status, 200);
  const verified = await response.json();
  assert.equal(verified.active, true);
  assert.equal(verified.receiptVerified, true);
  assert.equal(verified.acknowledged, true);
  assert.equal(verified.billingApiVersion, 2);
  assert.equal(acknowledgements, 1);
  assert.equal((await request('/billing/google/verify', '2', purchase)).status, 409);
  assert.equal((await request('/billing/google/verify', '2', { ...purchase, purchaseToken: 'another-purchase-token' })).status, 409);
  state = 'EXPIRED'; response = await request('/billing/entitlement');
  assert.equal((await response.json()).active, false);
  const count = acknowledgements;
  state = 'PENDING'; response = await request('/billing/google/verify', '1', purchase);
  const pending = await response.json();
  assert.equal(pending.active, false);
  assert.equal(pending.acknowledged, false);
  assert.equal(pending.receiptState, 'SUBSCRIPTION_STATE_PENDING');
  assert.equal(acknowledgements, count);
  assert.equal((await request('/billing/google/verify', '1', { ...purchase, productId: 'fake' })).status, 400);
});
