require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
  clientId: process.env.SPOTIFY_CLIENT_ID,
  clientSecret: process.env.SPOTIFY_CLIENT_SECRET,
  clientCallbackUrl: process.env.SPOTIFY_CLIENT_CALLBACK_URL,
  encryptionSecret: process.env.ENCRYPTION_SECRET,
};

// Validate required configuration
function validateConfig() {
  if (!config.clientId || !config.clientSecret || !config.clientCallbackUrl) {
    throw new Error('client credentials are empty');
  }
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
  const credentials = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64');

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

// POST /api/spotify/token
// Convert an authorization code to an access token.
app.post('/api/spotify/token', async (req, res) => {
  try {
    const code = req.body.code;

    if (!code) {
      return res.status(400).json({ error: 'code is required' });
    }

    const { status, data } = await spotifyRequest('authorization_code', {
      code,
      redirect_uri: config.clientCallbackUrl,
    });

    // Encrypt refresh token if encryption is enabled
    if (data.refresh_token && config.encryptionSecret) {
      data.refresh_token = encrypt(data.refresh_token);
    }

    res.status(status).json(data);
  } catch (err) {
    res.status(400).json({ error: err.message || err });
  }
});

// POST /api/spotify/refresh_token
// Use a refresh token to generate a one-hour access token.
app.post('/api/spotify/refresh_token', async (req, res) => {
  try {
    let refreshToken = req.body.refresh_token;

    if (!refreshToken) {
      return res.status(400).json({ error: 'refresh_token is required' });
    }

    // Handle escaped newlines
    refreshToken = refreshToken.replace(/\\n/g, '\n');

    // Decrypt if encryption is enabled
    if (config.encryptionSecret) {
      refreshToken = decrypt(refreshToken);
    }

    const { status, data } = await spotifyRequest('refresh_token', {
      refresh_token: refreshToken,
    });

    res.status(status).json(data);
  } catch (err) {
    if (err.message === 'invalid refresh_token') {
      return res.status(400).json({ error: 'invalid refresh_token' });
    }
    res.status(400).json({ error: err.message || err });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Spotify Token Swap Service running on port ${PORT}`);
});

module.exports = app;
