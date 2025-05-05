#!/bin/bash
set -e

# Run Alembic migrations
echo "Running database migrations..."
alembic upgrade head

# Start the FastAPI service
echo "Starting Auth service..."
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
