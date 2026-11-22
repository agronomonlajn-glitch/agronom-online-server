'use strict';
const { initializeApp, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const projectId = 'agronomonline-68820';

// Signature, audience, issuer and expiry are verified by the Admin SDK using
// Google's public certificates. No Firebase user is created or migrated here.
function createFirebaseVerifier() {
  const name = 'agronom-billing-identity';
  const app = getApps().find(app => app.name === name) || initializeApp({ projectId }, name);
  return token => getAuth(app).verifyIdToken(token);
}
module.exports = { createFirebaseVerifier, projectId };
