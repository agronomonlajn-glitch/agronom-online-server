'use strict';
const { createHash } = require('node:crypto');
const { createFirebaseVerifier, projectId } = require('./firebase_identity');
const { GoogleAuth } = require('google-auth-library');
const packageName = 'ua.agronom.online';
const productId = 'agronom_premium_monthly';
const hash = value => createHash('sha256').update(String(value)).digest('hex');
const accountId = userId => hash(`agronom:${userId}`);

// Emit only fixed diagnostic labels, never SDK messages or token contents.
function identityFailureReason(error) {
  const message = String(error?.message || '');
  if (message.includes('audience')) return 'firebase_audience_mismatch';
  if (message.includes('issuer')) return 'firebase_issuer_mismatch';
  if (message.includes('signature')) return 'firebase_signature_invalid';
  if (message.includes('kid')) return 'firebase_key_id_invalid';
  const codes = {
    'auth/id-token-expired': 'firebase_token_expired',
    'auth/id-token-revoked': 'firebase_token_revoked',
    'auth/invalid-credential': 'firebase_credentials_invalid',
    'auth/invalid-argument': 'firebase_token_invalid',
    'app/invalid-credential': 'firebase_credentials_invalid',
    'app/network-error': 'firebase_certificate_network_error',
  };
  return codes[error?.code] || 'firebase_verification_failed';
}

function entitlement(purchase, now = Date.now()) {
  const allowed = ['SUBSCRIPTION_STATE_ACTIVE', 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
    'SUBSCRIPTION_STATE_CANCELED'];
  const expiry = Math.max(0, ...(purchase.lineItems || [])
    .filter(item => item.productId === productId)
    .map(item => Date.parse(item.expiryTime) || 0));
  return { active: allowed.includes(purchase.subscriptionState) && expiry > now,
    expiresAt: expiry ? new Date(expiry).toISOString() : null };
}

function registerBilling(app, { dbGet, dbRun, dbAll, googleClient,
  verifyFirebaseToken = createFirebaseVerifier() }) {
  let credentials, validConfiguration = true;
  if (process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON) {
    try {
      credentials = JSON.parse(process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON);
      validConfiguration = credentials !== null && typeof credentials === 'object' && !Array.isArray(credentials);
    } catch (_) { validConfiguration = false; }
  }
  const ready = Boolean(googleClient || (validConfiguration &&
    (process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON || process.env.GOOGLE_APPLICATION_CREDENTIALS)));
  const auth = new GoogleAuth({
    ...(validConfiguration && credentials ? { credentials } : {}),
    scopes: ['https://www.googleapis.com/auth/androidpublisher'],
  });
  const schema = dbRun(`CREATE TABLE IF NOT EXISTS play_subscriptions (
    token_hash TEXT PRIMARY KEY, token TEXT NOT NULL, user_id TEXT NOT NULL,
    product_id TEXT NOT NULL, expires_at TEXT, state TEXT, verified_at TEXT
  )`).then(() => dbRun('CREATE INDEX IF NOT EXISTS play_subscriptions_user ON play_subscriptions(user_id, expires_at)'));
  let catalogCheckedAt = 0;
  async function catalogReady() {
    if (!ready) return false;
    if (Date.now() - catalogCheckedAt < 300000) return true;
    try {
      const client = googleClient || await auth.getClient();
      const { data } = await client.request({
        url: `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/subscriptions/${productId}`,
        timeout: 15000,
      });
      const monthly = data.basePlans?.some(plan => plan.state === 'ACTIVE' &&
        plan.autoRenewingBasePlanType?.billingPeriodDuration === 'P1M');
      if (!monthly) return false;
      catalogCheckedAt = Date.now(); return true;
    } catch (_) { return false; }
  }
  app.get('/billing/status', async (_, res) => res.json({ billingReady: await catalogReady(),
    productId, identityProvider: 'firebase', firebaseProjectId: projectId, billingApiVersion: 2 }));
  async function authenticate(req, res, next) {
    try {
      const bearer = /^Bearer (\S+)$/.exec(String(req.headers.authorization || ''));
      if (!bearer || bearer[1].length > 16384) throw new Error('Invalid bearer');
      const claims = await verifyFirebaseToken(bearer[1]);
      if (typeof claims.uid !== 'string' || !claims.uid || claims.uid.length > 128) throw new Error('Invalid Firebase identity');
      req.billingUser = claims.uid;
      next();
    } catch (error) {
      console.warn('[BillingIdentity]', identityFailureReason(error));
      res.status(401).json({ error: 'Sign in required' });
    }
  }
  async function verify(token, userId, persist = true) {
    await schema;
    const old = await dbGet('SELECT * FROM play_subscriptions WHERE token_hash = ?', [hash(token)]);
    if (old && old.user_id !== userId) {
      const error = new Error('Purchase belongs to another account'); error.status = 409; throw error;
    }
    const client = googleClient || await auth.getClient();
    const root = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases`;
    const { data: purchase } = await client.request({
      url: `${root}/subscriptionsv2/tokens/${encodeURIComponent(token)}`, timeout: 15000,
    });
    const external = purchase.externalAccountIdentifiers?.obfuscatedExternalAccountId;
    if (external && external !== accountId(userId) && external !== userId) {
      const error = new Error('Purchase account mismatch'); error.status = 409; throw error;
    }
    if (purchase.linkedPurchaseToken) {
      const linked = await dbGet('SELECT user_id FROM play_subscriptions WHERE token_hash = ?',
        [hash(purchase.linkedPurchaseToken)]);
      if (linked && linked.user_id !== userId) {
        const error = new Error('Linked purchase account mismatch'); error.status = 409; throw error;
      }
    }
    if (!(purchase.lineItems || []).some(item => item.productId === productId)) {
      const error = new Error('Unexpected subscription product'); error.status = 400; throw error;
    }
    const result = entitlement(purchase);
    if (persist) {
      // Atomic ownership check also prevents two simultaneous legacy restores claiming a token.
      const written = await dbRun(`INSERT INTO play_subscriptions
        (token_hash, token, user_id, product_id, expires_at, state, verified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(token_hash) DO UPDATE SET expires_at=excluded.expires_at,
          state=excluded.state, verified_at=excluded.verified_at
        WHERE play_subscriptions.user_id=excluded.user_id`,
      [hash(token), token, userId, productId, result.expiresAt, purchase.subscriptionState,
        new Date().toISOString()]);
      if (!written.changes) {
        const error = new Error('Purchase belongs to another account'); error.status = 409; throw error;
      }
    }
    let acknowledged = purchase.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED';
    if (result.active && purchase.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_PENDING') {
      await client.request({ url: `${root}/subscriptions/${productId}/tokens/${encodeURIComponent(token)}:acknowledge`,
        method: 'POST', data: {}, timeout: 15000 });
      acknowledged = true;
    }
    return { ...result, acknowledged, state: purchase.subscriptionState };
  }
  async function latest(userId) {
    await schema;
    const rows = await dbAll(`SELECT token FROM play_subscriptions WHERE user_id = ?
      ORDER BY expires_at DESC LIMIT 10`, [userId]);
    let latest = { active: false, expiresAt: null };
    for (const row of rows) {
      try {
        const result = await verify(row.token, userId);
        if (result.active) return result;
      } catch (error) {
        if (![404, 410].includes(error.response?.status)) throw error;
      }
    }
    return latest;
  }
  async function handle(req, res, token) {
    if (!ready) return res.status(503).json({ billingReady: false, error: 'Billing verification unavailable' });
    try {
      const verified = token ? await verify(token, req.billingUser) : null;
      const result = verified?.active ? verified : await latest(req.billingUser);
      return res.json({ ...result, billingReady: await catalogReady(), productId,
        identityProvider: 'firebase', firebaseProjectId: projectId, billingApiVersion: 2,
        receiptVerified: Boolean(token && verified?.active && verified?.acknowledged),
        acknowledged: Boolean(token && verified?.acknowledged), receiptState: verified?.state || null,
        accountId: accountId(req.billingUser), verifiedAt: new Date().toISOString() });
    } catch (error) {
      // Never include raw Google errors or receipt tokens in logs/responses.
      const googleStatus = error.response?.status;
      if (googleStatus === 404 || googleStatus === 410) {
        return res.status(400).json({ error: 'Purchase not found' });
      }
      return res.status(error.status || 503).json({ error: error.status ? error.message : 'Purchase verification temporarily unavailable' });
    }
  }
  app.get('/billing/entitlement', authenticate, (req, res) => handle(req, res));
  app.post('/billing/google/verify', authenticate, (req, res) => {
    if (req.body.productId !== productId || typeof req.body.purchaseToken !== 'string' ||
        req.body.purchaseToken.length < 10 || req.body.purchaseToken.length > 10000) {
      return res.status(400).json({ error: 'Invalid purchase' });
    }
    return handle(req, res, req.body.purchaseToken);
  });
}
module.exports = { registerBilling, entitlement, accountId, identityFailureReason };
