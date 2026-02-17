require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
  spotify: {
    clientId: process.env.SPOTIFY_CLIENT_ID,
    clientSecret: process.env.SPOTIFY_CLIENT_SECRET,
    clientCallbackUrl: process.env.SPOTIFY_CLIENT_CALLBACK_URL,
  },
  strava: {
    clientId: process.env.STRAVA_CLIENT_ID,
    clientSecret: process.env.STRAVA_CLIENT_SECRET,
  },
  encryptionSecret: process.env.ENCRYPTION_SECRET,
};

// Validate that at least one service is configured
function validateConfig() {
  const hasSpotify = config.spotify.clientId && config.spotify.clientSecret && config.spotify.clientCallbackUrl;
  const hasStrava = config.strava.clientId && config.strava.clientSecret;
  if (!hasSpotify && !hasStrava) {
    throw new Error('No service configured. Set SPOTIFY_CLIENT_* or STRAVA_CLIENT_* env vars.');
  }
  if (hasSpotify) console.log('Spotify token service: enabled');
  if (hasStrava) console.log('Strava token service: enabled');
}

validateConfig();

// Middleware
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Encryption helpers
const ALGORITHM = 'aes-256-cbc';

function encrypt(text) {
  if (!config.encryptionSecret) return text;

  const key = crypto.scryptSync(config.encryptionSecret, 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  // Prepend IV for decryption
  return iv.toString('base64') + ':' + encrypted;
}

function decrypt(text) {
  if (!config.encryptionSecret) return text;

  try {
    const parts = text.split(':');
    if (parts.length !== 2) return text;

    const iv = Buffer.from(parts[0], 'base64');
    const encryptedText = parts[1];
    const key = crypto.scryptSync(config.encryptionSecret, 'salt', 32);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

    let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (err) {
    throw new Error('invalid refresh_token');
  }
}

// HTTP helper for Spotify API
async function spotifyRequest(grantType, params) {
  const credentials = Buffer.from(`${config.spotify.clientId}:${config.spotify.clientSecret}`).toString('base64');

  const body = new URLSearchParams({
    grant_type: grantType,
    ...params,
  });

  const response = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  const data = await response.json();
  return { status: response.status, data };
}

// HTTP helper for Strava API
async function stravaRequest(grantType, params) {
  const body = new URLSearchParams({
    client_id: config.strava.clientId,
    client_secret: config.strava.clientSecret,
    grant_type: grantType,
    ...params,
  });

  const response = await fetch('https://www.strava.com/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  const data = await response.json();
  return { status: response.status, data };
}

// POST /api/spotify/token
// Convert an authorization code to an access token.
app.post('/api/spotify/token', async (req, res) => {
  console.log('=== TOKEN SWAP REQUEST ===');
  console.log('Body:', JSON.stringify(req.body, null, 2));

  try {
    const code = req.body.code;

    if (!code) {
      console.log('ERROR: code is missing');
      return res.status(400).json({ error: 'code is required' });
    }

    console.log('Code received:', code.substring(0, 20) + '...');
    console.log('Redirect URI:', config.spotify.clientCallbackUrl);

    const { status, data } = await spotifyRequest('authorization_code', {
      code,
      redirect_uri: config.spotify.clientCallbackUrl,
    });

    console.log('Spotify API response status:', status);
    console.log('Has access_token:', !!data.access_token);
    console.log('Has refresh_token:', !!data.refresh_token);
    console.log('Expires in:', data.expires_in);

    // Encrypt refresh token if encryption is enabled
    if (data.refresh_token && config.encryptionSecret) {
      console.log('Encrypting refresh token...');
      data.refresh_token = encrypt(data.refresh_token);
    }

    res.status(status).json(data);
  } catch (err) {
    console.log('ERROR in token swap:', err.message || err);
    res.status(400).json({ error: err.message || err });
  }
});

// POST /api/spotify/refresh_token
// Use a refresh token to generate a one-hour access token.
app.post('/api/spotify/refresh_token', async (req, res) => {
  console.log('=== REFRESH TOKEN REQUEST ===');
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  console.log('Body:', JSON.stringify(req.body, null, 2));
  console.log('Raw body keys:', Object.keys(req.body));

  try {
    let refreshToken = req.body.refresh_token;

    console.log('Extracted refresh_token:', refreshToken ? `${refreshToken.substring(0, 20)}...` : 'MISSING');

    if (!refreshToken) {
      console.log('ERROR: refresh_token is missing from request body');
      return res.status(400).json({ error: 'refresh_token is required' });
    }

    // Handle escaped newlines
    refreshToken = refreshToken.replace(/\\n/g, '\n');

    // Decrypt if encryption is enabled
    if (config.encryptionSecret) {
      console.log('Decrypting refresh token...');
      refreshToken = decrypt(refreshToken);
      console.log('Decrypted refresh_token:', refreshToken ? `${refreshToken.substring(0, 20)}...` : 'FAILED');
    }

    console.log('Calling Spotify API for token refresh...');
    const { status, data } = await spotifyRequest('refresh_token', {
      refresh_token: refreshToken,
    });

    console.log('Spotify API response status:', status);
    console.log('Spotify API response:', JSON.stringify(data, null, 2));

    res.status(status).json(data);
  } catch (err) {
    console.log('ERROR in refresh:', err.message || err);
    if (err.message === 'invalid refresh_token') {
      return res.status(400).json({ error: 'invalid refresh_token' });
    }
    res.status(400).json({ error: err.message || err });
  }
});

// GET /api/strava/callback
// OAuth trampoline: Strava redirects here with ?code=...&state=routevideo://strava
// We redirect to the custom scheme URL so ASWebAuthenticationSession can intercept it.
app.get('/api/strava/callback', (req, res) => {
  const { code, state, scope, error } = req.query;
  console.log(`=== STRAVA OAUTH CALLBACK ===`);
  console.log('code:', code ? `${code.substring(0, 20)}...` : 'MISSING');
  console.log('state:', state);

  if (!state) {
    return res.status(400).send('Missing state parameter.');
  }

  // Build the deep link URL from the state parameter
  const separator = state.includes('?') ? '&' : '?';
  const params = new URLSearchParams();
  if (code) params.set('code', code);
  if (scope) params.set('scope', scope);
  if (error) params.set('error', error);
  const deepLink = `${state}${separator}${params.toString()}`;

  console.log('Redirecting to:', deepLink);

  // Redirect to the custom scheme — ASWebAuthenticationSession will catch this
  res.redirect(deepLink);
});

// POST /api/strava/token
// Handle both authorization_code exchange and refresh_token for Strava.
// The iOS app sends JSON: { grant_type, client_id, code } or { grant_type, client_id, refresh_token }
// This endpoint injects the client_secret and forwards to Strava.
app.post('/api/strava/token', async (req, res) => {
  const grantType = req.body.grant_type;
  console.log(`=== STRAVA TOKEN REQUEST (${grantType}) ===`);

  try {
    if (!config.strava.clientId || !config.strava.clientSecret) {
      return res.status(500).json({ error: 'Strava is not configured on the server.' });
    }

    if (grantType === 'authorization_code') {
      const code = req.body.code;
      if (!code) {
        return res.status(400).json({ error: 'code is required' });
      }

      console.log('Code received:', code.substring(0, 20) + '...');
      const { status, data } = await stravaRequest('authorization_code', { code });

      console.log('Strava API response status:', status);
      console.log('Has access_token:', !!data.access_token);
      console.log('Has refresh_token:', !!data.refresh_token);
      console.log('Expires at:', data.expires_at);

      res.status(status).json(data);
    } else if (grantType === 'refresh_token') {
      const refreshToken = req.body.refresh_token;
      if (!refreshToken) {
        return res.status(400).json({ error: 'refresh_token is required' });
      }

      console.log('Refreshing Strava token...');
      const { status, data } = await stravaRequest('refresh_token', {
        refresh_token: refreshToken,
      });

      console.log('Strava API response status:', status);
      console.log('Has access_token:', !!data.access_token);
      console.log('Expires at:', data.expires_at);

      res.status(status).json(data);
    } else {
      res.status(400).json({ error: `unsupported grant_type: ${grantType}` });
    }
  } catch (err) {
    console.log('ERROR in Strava token request:', err.message || err);
    res.status(500).json({ error: err.message || err });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Token Swap Service running on port ${PORT}`);
});

module.exports = app;
