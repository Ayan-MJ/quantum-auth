# Quantum Auth Service

The Auth service is a FastAPI-based backend service for the Quantum Auth platform. It provides authentication, key management, and recovery services using post-quantum cryptography.

## Features

- User authentication via Supabase JWT verification
- Post-quantum keypair management using the `crypto-sdk`
- Shamir secret sharing for key recovery
- tRPC endpoints for frontend integration
- RESTful API endpoints
- PostgreSQL database for data storage

## Tech Stack

- FastAPI: Web framework
- SQLAlchemy: ORM for database access
- Alembic: Database migrations
- Pydantic: Data validation
- PyNaCl: Cryptographic primitives
- Python-Jose: JWT handling
- Secretsharing: Shamir secret sharing
- HTTPX: HTTP client for async requests

## Setup

### Prerequisites

- Python 3.10+
- PostgreSQL
- Poetry (for dependency management)

### Installation

1. Install dependencies:

```bash
poetry install
```

2. Set up environment variables:

```bash
# Database connection
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/quantum_auth"

# Supabase configuration
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_JWT_SECRET="your-jwt-secret"

# CORS settings
export ALLOWED_ORIGINS="http://localhost:3000,https://your-domain.com"
```

3. Run database migrations:

```bash
alembic upgrade head
```

4. Start the server:

```bash
./scripts/start.sh
```

## API Endpoints

### Authentication

- `POST /api/v1/auth/signup`: Sign up a user
  - Returns: `{"user_id": "uuid", "is_new": true|false}`

### Key Management

- `POST /api/v1/keys`: Create a new key for a user
- `GET /api/v1/keys`: Get a user's key
- `PUT /api/v1/keys`: Update a user's key

### Recovery

- `POST /api/v1/recovery/shares`: Create recovery shares for a user
- `POST /api/v1/recovery/verify`: Verify recovery shares
- `POST /api/v1/recovery/key`: Recover a key using shares

## tRPC Endpoints

The Auth service also provides tRPC endpoints for frontend integration:

- `auth.signup`: Sign up a user
- `keys.create`: Create a new key for a user
- `keys.get`: Get a user's key
- `keys.update`: Update a user's key
- `recovery.createShares`: Create recovery shares for a user
- `recovery.verifyShares`: Verify recovery shares
- `recovery.recoverKey`: Recover a key using shares

## Testing

Run the tests with:

```bash
./scripts/test.sh
```

## Docker

Build and run the Docker container:

```bash
docker build -t quantum-auth-service .
docker run -p 8000:8000 quantum-auth-service
```

## CI/CD

The Auth service is deployed to Fly.io using GitHub Actions. The workflow is configured to avoid overlapping deploys during rapid pushes with:

```yaml
concurrency:
  group: ${{ github.head_ref }}-auth
  cancel-in-progress: true
```

## Development

For local development, you can use Docker Compose:

```bash
docker-compose up -d
```

This will start the Auth service, PostgreSQL database, and other required services.
