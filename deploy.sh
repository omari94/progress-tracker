#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "📦 Committing..."
git add -A
git commit -m "${1:-update}" || echo "Nothing to commit"

echo "🚀 Pushing to GitHub..."
git push

echo "🔄 Deploying to EC2..."
ssh -i ~/.ssh/EC21.pem ubuntu@54.246.157.119 \
  "cd /home/ubuntu/tracker-git && git pull && COMPOSE_BAKE=false docker compose up --build -d"

echo "✅ Done — https://54.246.157.119:8090"
