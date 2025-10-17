import { NextRequest, NextResponse } from "next/server";
import { authenticator } from "otplib";
import { prisma } from "@/lib/prisma";
import { getSessionUser } from "@/lib/auth";
import crypto from "crypto";

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

    const body = await req.json();
    const { code } = body;

    if (!code || typeof code !== "string" || code.length !== 6) {
      return NextResponse.json(
        { error: "Invalid code format" },
        { status: 400 }
      );
    }

    // Get TOTP record
    const totp = await prisma.totp.findUnique({
      where: { userId: user.id },
    });

    if (!totp || !totp.secret) {
      return NextResponse.json(
        { error: "TOTP not set up. Please run setup first." },
        { status: 400 }
      );
    }

    // Verify the code
    const isValid = authenticator.check(code, totp.secret);

    if (!isValid) {
      return NextResponse.json(
        { error: "Invalid code" },
        { status: 400 }
      );
    }

    // Generate backup codes (10 codes)
    const backupCodes: string[] = [];
    for (let i = 0; i < 10; i++) {
      backupCodes.push(crypto.randomBytes(4).toString("hex").toUpperCase());
    }

    // Hash backup codes before storing
    const hashedBackupCodes = backupCodes.map((code) =>
      crypto.createHash("sha256").update(code).digest("hex")
    );

    // Enable TOTP and save backup codes
    await prisma.$transaction([
      prisma.totp.update({
        where: { userId: user.id },
        data: { 
          verified: true,
          lastUsedAt: new Date(),
        },
      }),
      prisma.backupCode.deleteMany({
        where: { userId: user.id },
      }),
      prisma.backupCode.createMany({
        data: hashedBackupCodes.map((hash) => ({
          userId: user.id,
          codeHash: hash,
        })),
      }),
    ]);

    // Log successful TOTP enable
    const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        event: "TOTP_ENROLL",
        ip,
        userAgent: req.headers.get("user-agent") || "unknown",
      },
    });

    return NextResponse.json({
      success: true,
      backupCodes, // Return plaintext codes ONCE for user to save
      message: "TOTP enabled successfully",
    });
  } catch (error) {
    console.error("TOTP verification error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
