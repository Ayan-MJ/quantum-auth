#!/bin/bash
set -e

# Run pytest with coverage
echo "Running tests with coverage..."
python -m pytest tests/ --cov=app --cov-report=term-missing --cov-report=xml:coverage.xml -v
