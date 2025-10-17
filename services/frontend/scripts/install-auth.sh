#!/usr/bin/env bash
set -euo pipefail

echo "📦 Installing authentication dependencies..."

PKGS=(
  "prisma"
  "@prisma/client"
  "@auth/prisma-adapter"
  "zod"
  "react-hook-form"
  "@hookform/resolvers"
  "@upstash/ratelimit"
  "@upstash/redis"
  "nodemailer"
)

DEV_PKGS=(
  "@types/nodemailer"
)

for p in "${PKGS[@]}"; do
  echo "Installing $p..."
  pnpm add "$p"
done

for p in "${DEV_PKGS[@]}"; do
  echo "Installing $p (dev)..."
  pnpm add -D "$p"
done

echo "✅ Initializing Prisma..."
npx prisma init || true

echo "✨ Done! Next steps:"
echo "1. Configure .env with DATABASE_URL and auth settings"
echo "2. Run: pnpm exec prisma migrate dev -n auth_base"
echo "3. Run: pnpm dev"
