import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { sendVerificationEmail } from "@/lib/email";
import bcrypt from "bcryptjs";
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
    prefix: "auth:register",
  });
}

// Validation schema
const registerSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z
    .string()
    .min(12, "Password must be at least 12 characters")
    .regex(/[a-z]/, "Password must contain lowercase letter")
    .regex(/[A-Z]/, "Password must contain uppercase letter")
    .regex(/[0-9]/, "Password must contain number")
    .regex(/[^a-zA-Z0-9]/, "Password must contain special character"),
  name: z.string().min(1).max(100).optional(),
});

export async function POST(req: NextRequest) {
  try {
    // Rate limit check
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";
    
    if (ratelimit) {
      const { success } = await ratelimit.limit(`ip:${ip}`);
      if (!success) {
        return NextResponse.json(
          { error: "Too many requests. Please try again later." },
          { status: 429 }
        );
      }
    }

    // Parse and validate input
    const body = await req.json();
    const { email, password, name } = registerSchema.parse(body);

    // Additional rate limit by email
    if (ratelimit) {
      const { success } = await ratelimit.limit(`email:${email}`);
      if (!success) {
        return NextResponse.json(
          { error: "Too many requests. Please try again later." },
          { status: 429 }
        );
      }
    }

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
      select: { id: true, emailVerified: true },
    });

    if (existingUser) {
      const isDev = process.env.NODE_ENV !== "production";
      let debug: any = undefined;
      // If email not verified, resend verification
      if (!existingUser.emailVerified) {
        // Delete old tokens
        await prisma.verificationToken.deleteMany({
          where: { identifier: email },
        });

        // Generate new token
        const token = crypto.randomBytes(32).toString("hex");
        const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

        await prisma.verificationToken.create({
          data: {
            identifier: email,
            token,
            expires,
          },
        });

        // Send email
        await sendVerificationEmail(email, token);
        if (isDev) debug = { status: "existing-unverified", resent: true };
      }

      // Neutral response (no user enumeration)
      return NextResponse.json(
        {
          success: true,
          message: "If that email is not yet registered, we've sent a verification link.",
          ...(debug ? { debug } : {}),
        },
        { status: 200 }
      );
    }

    // Hash password
    const hash = await bcrypt.hash(password, 12);

    // Create user and password
    const user = await prisma.user.create({
      data: {
        email,
        name: name || null,
        password: {
          create: {
            hash,
          },
        },
      },
    });

    // Generate verification token
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    await prisma.verificationToken.create({
      data: {
        identifier: email,
        token,
        expires,
      },
    });

    // Send verification email
    await sendVerificationEmail(email, token);

    // Audit log
    await prisma.auditLog.create({
      data: {
        event: "EMAIL_VERIFY",
        userId: user.id,
        ip,
        userAgent: req.headers.get("user-agent") ?? undefined,
        meta: { action: "issued" },
      },
    });

    return NextResponse.json(
      {
        success: true,
        message: "Registration successful! Please check your email to verify your account.",
        ...(process.env.NODE_ENV !== "production" ? { debug: { status: "created" } } : {}),
      },
      { status: 201 }
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.issues[0].message },
        { status: 400 }
      );
    }

    console.error("Registration error:", error);
    return NextResponse.json(
      { error: "An error occurred during registration." },
      { status: 500 }
    );
  }
}

export const runtime = "nodejs";
