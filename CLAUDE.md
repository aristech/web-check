# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Web-Check is an OSINT (Open Source Intelligence) tool for analyzing websites. It performs 30+ security and information checks on any URL, IP, or domain. The codebase is a full-stack Astro application with a React frontend and Node.js/Express backend API.

## Development Commands

```bash
# Full development (backend + frontend concurrently)
yarn dev

# Backend API only (port 3001)
yarn dev:api

# Frontend only (connects to API at localhost:3001)
yarn dev:astro

# Build for production
yarn build

# Run production server (port 3000)
yarn start
```

## Architecture

### Frontend-Backend Split

The application runs as two concurrent processes in development:
- **Backend**: Express server (`server.js`) on port 3001 serving `/api/*` endpoints
- **Frontend**: Astro dev server with React components, proxying API requests

In production, a single Express server serves both the API and the compiled Astro/React frontend from `dist/`.

### API Layer (`/api/`)

Each file in `/api/` is a standalone endpoint (33 total). All endpoints:
- Are wrapped by `/api/_common/middleware.js` which handles URL normalization, timeouts, CORS, and multi-platform response formatting
- Accept a `?url=` query parameter
- Return JSON responses

Key endpoints: `dns`, `ssl`, `whois`, `headers`, `tech-stack`, `screenshot`, `security-txt`, `ports`, `threats`, `firewall`

The `/api` root endpoint executes ALL handlers in parallel and returns consolidated results.

### Frontend (`/src/web-check-live/`)

React SPA with client-side routing:
- **Entry**: `main.tsx` → `App.tsx` (React Router)
- **Routes**: `/check` → Home, `/check/:urlToScan` → Results
- **Results view** (`views/Results.tsx`): Orchestrates 40+ parallel API calls using `useMotherHook`
- **Result cards** (`components/Results/`): 38 modular components, one per scan type (e.g., `DnsRecords.tsx`, `SslCert.tsx`)

### State Management Pattern

The `useMotherHook` hook (`hooks/motherOfAllHooks.ts`) manages individual API fetches with:
- Loading/error/timeout states
- Retry logic
- Address type validation (URL vs IP vs domain)

### Multi-Platform Deployment

Configured via `PLATFORM` env var in `astro.config.mjs`:
- `node` (default): Express middleware mode
- `vercel`: Serverless functions
- `netlify`: Netlify functions
- `cloudflare`: Cloudflare Workers

## Key Environment Variables

- `PORT`: Server port (default: 3000)
- `PLATFORM`: Deploy target (node/vercel/netlify/cloudflare)
- `API_TIMEOUT_LIMIT`: Request timeout in ms (default: 60000)
- `API_CORS_ORIGIN`: CORS allowed origins (default: *)
- `API_ENABLE_RATE_LIMIT`: Enable rate limiting (true/false)
- `DISABLE_GUI`: Run API-only mode
- `PUBLIC_API_ENDPOINT`: Frontend API base URL (for dev: http://localhost:3001/api)

## File Structure Notes

- `/api/_common/middleware.js`: Shared middleware for all API endpoints
- `/src/pages/`: Astro pages (marketing + check entry point)
- `/src/web-check-live/`: Main React application
- `/src/web-check-live/utils/result-processor.ts`: API response transformations
- `/src/web-check-live/utils/address-type-checker.ts`: Input type detection (URL/IP/domain)
