# SponsorForm API

Collect sponsor data via custom forms, retrieve as JSON via API.

## Features
- Create custom sponsor forms
- Unique form URLs for each sponsor
- JSON API for retrieving submissions
- Webhook support (Pro)
- Stripe payment integration

## Quick Start

```bash
# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env with your values

# Run locally
npm run dev
```

## Deployment

### Railway
1. Push to GitHub
2. Connect Railway to repo
3. Set environment variables
4. Deploy

### Fly.io
```bash
fly launch
fly secrets set JWT_SECRET=xxx STRIPE_SECRET_KEY=xxx
```

## API Usage

```bash
# Get your forms
curl -H "Authorization: Bearer YOUR_TOKEN" /api/forms

# Get submissions
curl -H "Authorization: Bearer YOUR_TOKEN" "/api/submissions?form_id=1"
```