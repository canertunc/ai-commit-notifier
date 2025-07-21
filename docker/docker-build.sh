#!/bin/bash

# AI Commit Notifier - Docker Build Script
# Usage: ./docker-build.sh [--no-cache]

set -e

echo "🐳 Building AI Commit Notifier..."

# Go to project root
cd "$(dirname "$0")/.."

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found!"
    echo "Please copy: cp env.template .env"
    echo "Then edit .env file with your API keys"
    exit 1
fi

# Create logs directory
mkdir -p logs

# Parse arguments
CACHE_FLAG=""
if [ "$1" == "--no-cache" ]; then
    CACHE_FLAG="--no-cache"
fi

# Build and start
echo "Building Docker image..."
docker build $CACHE_FLAG -f docker/Dockerfile -t ai-commit-notifier:latest .

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    echo ""
    echo "Starting application..."
    docker-compose -f docker/docker-compose.yml up -d
    
    echo ""
    echo "🎉 AI Commit Notifier is running!"
    echo "Test with: curl http://localhost:5000/health"
else
    echo "❌ Build failed!"
    exit 1
fi 