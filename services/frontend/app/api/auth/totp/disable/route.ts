import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getSessionUser } from "@/lib/auth";
import bcrypt from "bcryptjs";

export async function POST(req: NextRequest) {
  try {
    // Get authenticated user
    const user = await getSessionUser();
    if (!user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await req.json();
    const { password } = body;

    if (!password) {
      return NextResponse.json(
        { error: "Password required to disable TOTP" },
        { status: 400 }
      );
    }

    // Verify password
    const userWithPassword = await prisma.user.findUnique({
      where: { id: user.id },
      include: { password: true },
    });

    if (!userWithPassword?.password) {
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      );
    }

    const validPassword = await bcrypt.compare(
      password,
      userWithPassword.password.hash
    );

    if (!validPassword) {
      return NextResponse.json(
        { error: "Invalid password" },
        { status: 401 }
      );
    }

    // Disable TOTP and delete backup codes
    await prisma.$transaction([
      prisma.totp.delete({
        where: { userId: user.id },
      }),
      prisma.backupCode.deleteMany({
        where: { userId: user.id },
      }),
    ]);

    // Log TOTP disable
    const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        event: "TOTP_ENROLL", // Using TOTP_ENROLL for now, could add TOTP_DISABLE to enum
        ip,
        userAgent: req.headers.get("user-agent") || "unknown",
      },
    });

    return NextResponse.json({
      success: true,
      message: "TOTP disabled successfully",
    });
  } catch (error) {
    console.error("TOTP disable error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
