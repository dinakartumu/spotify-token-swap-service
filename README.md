# Spotify Token Swap Service (Node.js)

A simple Node.js/Express service for Spotify OAuth token swapping, supporting the Authorization Code Flow.

## Why Use This?

When building iOS, Android, or web apps with Spotify authentication, you need to exchange authorization codes for access tokens. Doing this directly in your app exposes your client secret. This service handles the exchange securely on the server side.

## Endpoints

### POST /api/spotify/token

Exchange an authorization code for access and refresh tokens.

```bash
curl -X POST https://your-app.vercel.app/api/spotify/token \
  -d "code=YOUR_AUTH_CODE"
```

**Response:**
```json
{
  "access_token": "BQDjrNCJ66N1...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "p7jJ+3agZ8m9...",
  "scope": "user-read-private"
}
```

### POST /api/spotify/refresh_token

Use a refresh token to get a new access token.

```bash
curl -X POST https://your-app.vercel.app/api/spotify/refresh_token \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

**Response:**
```json
{
  "access_token": "BQCjHuWkG2pS...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "user-read-private"
}
```

## Deploy to Vercel

1. Click the button below or run `npx vercel`

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/dinakartumu/spotify-token-swap-service)

2. Set environment variables in Vercel dashboard:
   - `SPOTIFY_CLIENT_ID` - Your Spotify app client ID
   - `SPOTIFY_CLIENT_SECRET` - Your Spotify app client secret
   - `SPOTIFY_CLIENT_CALLBACK_URL` - Your app's redirect URI
   - `ENCRYPTION_SECRET` (optional) - Secret for encrypting refresh tokens

## Local Development

```bash
# Clone the repo
git clone https://github.com/dinakartumu/spotify-token-swap-service.git
cd spotify-token-swap-service

# Install dependencies
npm install

# Configure environment
cp .sample.env .env
# Edit .env with your Spotify credentials

# Run the server
npm run dev
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SPOTIFY_CLIENT_ID` | Your Spotify app client ID | Yes |
| `SPOTIFY_CLIENT_SECRET` | Your Spotify app client secret | Yes |
| `SPOTIFY_CLIENT_CALLBACK_URL` | Redirect URI registered in Spotify | Yes |
| `ENCRYPTION_SECRET` | Secret for encrypting refresh tokens | No |
| `PORT` | Server port (default: 3000) | No |

## License

MIT
