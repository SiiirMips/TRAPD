import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { sendVerificationEmail } from "@/lib/email";
import { z } from "zod";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import crypto from "crypto";

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
    prefix: "auth:resend-verify",
  });
}

const schema = z.object({ email: z.string().email().toLowerCase().trim() });

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";
    if (ratelimit) {
      const { success } = await ratelimit.limit(`ip:${ip}`);
      if (!success) return NextResponse.json({ success: true }, { status: 200 });
    }

    const body = await req.json();
    const { email } = schema.parse(body);

    const user = await prisma.user.findUnique({ where: { email }, select: { id: true, emailVerified: true } });

    if (!user) {
      // Neutral response
      return NextResponse.json({ success: true }, { status: 200 });
    }

    if (user.emailVerified) {
      // Already verified; neutral
      return NextResponse.json({ success: true }, { status: 200 });
    }

    // Clear previous tokens
    await prisma.verificationToken.deleteMany({ where: { identifier: email } });

    // Create new token
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await prisma.verificationToken.create({ data: { identifier: email, token, expires } });

    // Send
    await sendVerificationEmail(email, token);

    return NextResponse.json({ success: true }, { status: 200 });
  } catch (error) {
    return NextResponse.json({ success: true }, { status: 200 });
  }
}

export const runtime = "nodejs";
