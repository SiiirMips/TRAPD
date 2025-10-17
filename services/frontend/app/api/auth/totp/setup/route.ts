import { NextRequest, NextResponse } from "next/server";
import { authenticator } from "otplib";
import { prisma } from "@/lib/prisma";
import { getSessionUser } from "@/lib/auth";

// Configure authenticator options
authenticator.options = {
  window: 1, // Allow 1 step before/after for time sync issues
};

export async function POST(req: NextRequest) {
  try {
    // Get authenticated user
    const user = await getSessionUser();
    if (!user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Check if TOTP is already verified
    const existingTotp = await prisma.totp.findUnique({
      where: { userId: user.id },
    });

    if (existingTotp && existingTotp.verified) {
      return NextResponse.json(
        { error: "TOTP already enabled" },
        { status: 400 }
      );
    }

    // Generate new secret (Base32 encoded)
    const secret = authenticator.generateSecret();

    console.log("Generated TOTP secret:", {
      secret,
      length: secret.length,
    });

    // Create otpauth URL for QR code
    const otpauth = authenticator.keyuri(
      user.email || user.id,
      "TRAPD",
      secret
    );

    console.log("Generated otpauth URL:", otpauth);

    // Save or update TOTP record (not verified yet, only after verification)
    await prisma.totp.upsert({
      where: { userId: user.id },
      update: {
        secret,
        verified: false, // Will be verified after code check
      },
      create: {
        userId: user.id,
        secret,
        verified: false,
      },
    });

    // Log setup attempt
    const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        event: "TOTP_ENROLL",
        ip,
        userAgent: req.headers.get("user-agent") || "unknown",
      },
    });

    return NextResponse.json({ otpauth, secret });
  } catch (error) {
    console.error("TOTP setup error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
