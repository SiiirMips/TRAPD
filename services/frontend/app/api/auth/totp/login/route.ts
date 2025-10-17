import { NextRequest, NextResponse } from "next/server";
import { authenticator } from "otplib";
import { prisma } from "@/lib/prisma";
import crypto from "crypto";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Configure authenticator options
authenticator.options = {
  window: 1, // Allow 1 step before/after for time sync issues
};

// Rate limiting
let ratelimit: Ratelimit | null = null;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });
  ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(5, "15 m"),
    analytics: true,
    prefix: "totp:login",
  });
}

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
  
  try {
    const body = await req.json();
    const { userId, code, useBackup } = body;

    if (!userId || !code) {
      return NextResponse.json(
        { error: "User ID and code required" },
        { status: 400 }
      );
    }

    // Rate limiting by userId AND IP (BSI: Defense in depth)
    
    if (ratelimit) {
      const userLimit = await ratelimit.limit(`user:${userId}`);
      const ipLimit = await ratelimit.limit(`ip:${ip}`);
      
      if (!userLimit.success || !ipLimit.success) {
        // Log rate limit violation
        await prisma.auditLog.create({
          data: {
            userId,
            event: "LOGIN_FAILED",
            ip,
            userAgent: req.headers.get("user-agent") || "unknown",
            meta: { reason: "rate_limit_totp" },
          },
        });
        
        return NextResponse.json(
          { error: "Too many attempts. Please try again later." },
          { status: 429 }
        );
      }
    }

    // Get user with TOTP
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { 
        totp: true,
        backups: true,
      },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Handle backup code verification
    if (useBackup) {
      if (!user.backups || user.backups.length === 0) {
        return NextResponse.json(
          { error: "No backup codes available" },
          { status: 400 }
        );
      }

      // Hash the provided code
      const codeHash = crypto.createHash("sha256").update(code).digest("hex");

      // Find matching unused backup code
      const backupCode = user.backups.find(
        (bc: any) => bc.codeHash === codeHash && !bc.usedAt
      );

      if (!backupCode) {
        await prisma.auditLog.create({
          data: {
            userId: user.id,
            event: "LOGIN_FAILED",
            ip,
            userAgent: req.headers.get("user-agent") || "unknown",
            meta: { reason: "invalid_backup_code" },
          },
        });
        return NextResponse.json(
          { error: "Invalid or already used backup code" },
          { status: 400 }
        );
      }

      // Mark backup code as used
      await prisma.backupCode.update({
        where: { id: backupCode.id },
        data: { usedAt: new Date() },
      });

      await prisma.auditLog.create({
        data: {
          userId: user.id,
          event: "LOGIN_SUCCESS",
          ip,
          userAgent: req.headers.get("user-agent") || "unknown",
          meta: { method: "backup_code" },
        },
      });

      return NextResponse.json({
        success: true,
        message: "Backup code verified successfully",
      });
    }

    // Handle TOTP verification
    if (!user.totp || !user.totp.verified) {
      return NextResponse.json(
        { error: "TOTP not set up for this user" },
        { status: 400 }
      );
    }

    // Verify the TOTP code
    const isValid = authenticator.check(code, user.totp.secret);

    if (!isValid) {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          event: "LOGIN_FAILED",
          ip,
          userAgent: req.headers.get("user-agent") || "unknown",
          meta: { reason: "invalid_totp" },
        },
      });
      return NextResponse.json(
        { error: "Invalid TOTP code" },
        { status: 400 }
      );
    }

    // Update last used timestamp
    await prisma.totp.update({
      where: { userId: user.id },
      data: { lastUsedAt: new Date() },
    });

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        event: "LOGIN_SUCCESS",
        ip,
        userAgent: req.headers.get("user-agent") || "unknown",
        meta: { method: "totp" },
      },
    });

    // Create a cryptographically secure temporary token (BSI-compliant)
    // Using 256-bit (32 bytes) random token as per BSI recommendations
    const loginToken = crypto.randomBytes(32).toString("base64url");
    const expires = new Date(Date.now() + 2 * 60 * 1000); // 2 minutes (reduced from 5 for security)

    // Hash the token before storing (defense in depth)
    const tokenHash = crypto.createHash("sha256").update(loginToken).digest("hex");

    // Delete any existing tokens for this user (prevent token reuse attacks)
    await prisma.verificationToken.deleteMany({
      where: {
        identifier: `totp-login:${user.email}`,
      },
    });

    // Store hashed token in database
    await prisma.verificationToken.create({
      data: {
        identifier: `totp-login:${user.email}`,
        token: tokenHash, // Store hash, not plaintext
        expires,
      },
    });

    return NextResponse.json({
      success: true,
      message: "TOTP verified successfully",
      loginToken, // Send plaintext to client (only once)
      userId: user.id,
    });
  } catch (error) {
    console.error("TOTP login verification error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
