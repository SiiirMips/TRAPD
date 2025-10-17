import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { sendPasswordResetEmail } from "@/lib/email";
import { z } from "zod";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import crypto from "crypto";

// Rate limiter
let ratelimit: Ratelimit | null = null;

if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });

  ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(3, "10 m"),
    analytics: true,
    prefix: "auth:password-reset",
  });
}

const resetRequestSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
});

export async function POST(req: NextRequest) {
  try {
    // Rate limit check
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";
    
    if (ratelimit) {
      const ipLimit = await ratelimit.limit(`ip:${ip}`);
      if (!ipLimit.success) {
        return NextResponse.json(
          { error: "Too many requests. Please try again later." },
          { status: 429 }
        );
      }
    }

    const body = await req.json();
    const { email } = resetRequestSchema.parse(body);

    // Additional rate limit by email
    if (ratelimit) {
      const emailLimit = await ratelimit.limit(`email:${email}`);
      if (!emailLimit.success) {
        return NextResponse.json(
          { error: "Too many requests. Please try again later." },
          { status: 429 }
        );
      }
    }

    // Find user (but don't reveal if they exist)
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (user) {
      // Delete old password reset tokens for this email
      await prisma.verificationToken.deleteMany({
        where: {
          identifier: `reset:${email}`,
        },
      });

      // Generate reset token
      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

      await prisma.verificationToken.create({
        data: {
          identifier: `reset:${email}`,
          token,
          expires,
        },
      });

      // Send reset email
      await sendPasswordResetEmail(email, token);

      // Audit log
      await prisma.auditLog.create({
        data: {
          event: "PASSWORD_RESET",
          userId: user.id,
          ip,
          userAgent: req.headers.get("user-agent") ?? undefined,
          meta: { action: "requested" },
        },
      });
    }

    // Always return success (no user enumeration)
    return NextResponse.json(
      {
        success: true,
        message: "If that email exists, a password reset link has been sent.",
      },
      { status: 200 }
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid email address." },
        { status: 400 }
      );
    }

    console.error("Password reset request error:", error);
    return NextResponse.json(
      { error: "An error occurred. Please try again." },
      { status: 500 }
    );
  }
}

export const runtime = "nodejs";
