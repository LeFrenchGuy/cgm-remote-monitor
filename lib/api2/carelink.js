'use strict';

var express = require('express');
var consts = require('../constants');

function init (env, ctx) {
  var router = express();
  var auth = null;
  var oauth = null;

  // Lazy-load nightscout-connect auth modules
  try {
    auth = require('nightscout-connect/lib/sources/minimedcarelink/auth');
    oauth = require('nightscout-connect/lib/sources/minimedcarelink/oauth');
  } catch (e) {
    console.log('[CareLink API] nightscout-connect not available:', e.message);
  }

  // In-memory store for pending PKCE sessions (state -> { codeVerifier, ssoConfig, baseUrl, createdAt })
  var pendingSessions = {};

  // Clean up expired sessions (older than 10 minutes)
  function cleanupSessions () {
    var now = Date.now();
    var keys = Object.keys(pendingSessions);
    for (var i = 0; i < keys.length; i++) {
      if (now - pendingSessions[keys[i]].createdAt > 10 * 60 * 1000) {
        delete pendingSessions[keys[i]];
      }
    }
  }

  var wares = require('../middleware/index')(env);
  router.use(wares.sendJSONStatus);
  router.use(wares.bodyParser.json());
  router.use(wares.bodyParser.urlencoded({ extended: true }));

  /**
   * POST /api/v2/carelink/auth-url
   *
   * Initiates the CareLink OAuth2 PKCE flow.
   * Body: { region: 'us' | 'eu' }
   * Returns: { authorizeUrl, state }
   */
  router.post('/auth-url', ctx.authorization.isPermitted('admin:api:carelink:auth'), function (req, res) {
    if (!auth) {
      return res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'CareLink auth module not available', 'nightscout-connect not installed');
    }

    var region = (req.body.region || 'eu').toLowerCase();
    var isUS = region === 'us';
    var axios = require('axios');

    cleanupSessions();

    auth.discoverAuth0Config(isUS, axios)
      .then(function (config) {
        var pkce = auth.generatePKCE();
        var authUrl = auth.buildAuthorizeUrl(config.ssoConfig, config.baseUrl, pkce.codeChallenge);

        pendingSessions[authUrl.state] = {
          codeVerifier: pkce.codeVerifier,
          ssoConfig: config.ssoConfig,
          baseUrl: config.baseUrl,
          createdAt: Date.now(),
        };

        res.json({
          authorizeUrl: authUrl.url,
          state: authUrl.state,
        });
      })
      .catch(function (err) {
        console.log('[CareLink API] Discovery failed:', err.message);
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'CareLink discovery failed', err.message);
      });
  });

  /**
   * POST /api/v2/carelink/exchange
   *
   * Completes the OAuth2 flow by exchanging the authorization code for tokens.
   * Body: { state, callbackUrl }
   * Returns: { success, message }
   */
  router.post('/exchange', ctx.authorization.isPermitted('admin:api:carelink:auth'), function (req, res) {
    if (!auth || !oauth) {
      return res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'CareLink auth module not available', 'nightscout-connect not installed');
    }

    var state = req.body.state;
    var callbackUrl = req.body.callbackUrl;

    if (!state || !callbackUrl) {
      return res.sendJSONStatus(res, consts.HTTP_BAD_REQUEST, 'Missing parameters', 'state and callbackUrl are required');
    }

    var session = pendingSessions[state];
    if (!session) {
      return res.sendJSONStatus(res, consts.HTTP_BAD_REQUEST, 'Invalid or expired session', 'PKCE session not found. Start over.');
    }

    var code = auth.extractCodeFromUrl(callbackUrl);
    if (!code) {
      return res.sendJSONStatus(res, consts.HTTP_BAD_REQUEST, 'No authorization code found', 'The URL does not contain a code= parameter.');
    }

    var axios = require('axios');

    auth.exchangeCodeForTokens(session.ssoConfig, session.baseUrl, code, session.codeVerifier, axios)
      .then(function (loginData) {
        // Clean up the used session
        delete pendingSessions[state];

        // Save logindata.json
        var path = require('path');
        var loginDataPath = env.extendedSettings && env.extendedSettings.connect && env.extendedSettings.connect.carelinkLoginData;
        if (!loginDataPath) {
          loginDataPath = path.join(process.cwd(), 'logindata.json');
        }
        oauth.saveLoginData(loginDataPath, loginData);

        // Decode token for display info
        var payload = oauth.decodeJwtPayload(loginData.access_token);
        var expiresIn = payload && payload.exp ? Math.floor((payload.exp * 1000 - Date.now()) / 60000) : null;
        var country = payload && payload.token_details ? payload.token_details.country : null;

        console.log('[CareLink API] Login successful, tokens saved to', loginDataPath);

        res.json({
          success: true,
          message: 'CareLink authentication successful. Tokens saved.',
          loginDataPath: loginDataPath,
          expiresInMinutes: expiresIn,
          country: country,
        });
      })
      .catch(function (err) {
        console.log('[CareLink API] Token exchange failed:', err.message);
        delete pendingSessions[state];
        res.sendJSONStatus(res, consts.HTTP_INTERNAL_ERROR, 'Token exchange failed', err.message);
      });
  });

  /**
   * GET /api/v2/carelink/status
   *
   * Returns the current CareLink authentication status.
   */
  router.get('/status', ctx.authorization.isPermitted('admin:api:carelink:read'), function (req, res) {
    if (!oauth) {
      return res.json({ configured: false, message: 'nightscout-connect not installed' });
    }

    var path = require('path');
    var loginDataPath = env.extendedSettings && env.extendedSettings.connect && env.extendedSettings.connect.carelinkLoginData;
    if (!loginDataPath) {
      loginDataPath = path.join(process.cwd(), 'logindata.json');
    }

    var loaded = oauth.loadLoginData(loginDataPath);
    if (!loaded.data) {
      return res.json({ configured: false, message: 'logindata.json not found or invalid' });
    }

    var expired = oauth.isTokenExpired(loaded.data.access_token);
    var region = oauth.detectRegion(loaded.data);
    var payload = oauth.decodeJwtPayload(loaded.data.access_token);
    var expiresIn = payload && payload.exp ? Math.floor((payload.exp * 1000 - Date.now()) / 60000) : null;

    res.json({
      configured: true,
      tokenExpired: expired,
      region: region,
      expiresInMinutes: expiresIn,
      message: expired ? 'Token expired — will be refreshed on next cycle' : 'Token valid',
    });
  });

  return router;
}

module.exports = init;
