# Quantum Auth

Secure authentication system with post-quantum cryptography.

## Architecture

```
                           ┌──────────────┐
                           │              │
                           │   Traefik    │
                           │   Gateway    │
                           │              │
                           └───────┬──────┘
                                   │
                 ┌─────────────────┼─────────────────┐
                 │                 │                 │
        ┌────────▼─────┐  ┌────────▼─────┐  ┌────────▼─────┐
        │              │  │              │  │              │
        │  Next.js     │  │  Auth        │  │  Postgres    │
        │  Web App     │  │  Service     │  │  Database    │
        │              │  │              │  │              │
        └──────────────┘  └──────┬───────┘  └──────────────┘
                                 │
                       ┌─────────▼────────┐
                       │                  │
                       │   Crypto SDK     │
                       │                  │
                       └──────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Node.js (v18+)
- pnpm (v8.9.0+)
- Direnv (optional but recommended)

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/quantum-auth.git
   cd quantum-auth
   ```

2. Set up environment variables:

   ```bash
   cp .env.example .env
   direnv allow  # If using direnv
   ```

3. Install dependencies:

   ```bash
   pnpm install
   ```

4. Start the development environment:

   ```bash
   docker-compose up --build
   ```

5. Access the applications:
   - Web UI: http://localhost:3000
   - API: http://localhost/api/ping
   - Traefik Dashboard: http://localhost:8080

## Development

### Running Services Individually

- Web App: `pnpm --filter web dev`
- Auth Service: `cd services/auth && poetry run ./scripts/start.sh`

### Running Tests

```bash
pnpm test
```

### Linting

```bash
pnpm lint
```

## Project Structure

- `apps/web`: Next.js web application
- `packages/crypto-sdk`: Shared crypto utilities
- `services/auth`: FastAPI authentication service
- `.github`: GitHub Actions workflows
