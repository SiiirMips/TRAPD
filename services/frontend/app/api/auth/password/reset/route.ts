import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";

const resetSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  token: z.string().min(1),
  password: z
    .string()
    .min(12, "Password must be at least 12 characters")
    .regex(/[a-z]/, "Password must contain lowercase letter")
    .regex(/[A-Z]/, "Password must contain uppercase letter")
    .regex(/[0-9]/, "Password must contain number")
    .regex(/[^a-zA-Z0-9]/, "Password must contain special character"),
});

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { email, token, password } = resetSchema.parse(body);

    // Find reset token
    const resetToken = await prisma.verificationToken.findUnique({
      where: {
        identifier_token: {
          identifier: `reset:${email}`,
          token,
        },
      },
    });

    if (!resetToken) {
      return NextResponse.json(
        { error: "Invalid or expired reset link." },
        { status: 400 }
      );
    }

    // Check if expired
    if (resetToken.expires < new Date()) {
      await prisma.verificationToken.delete({
        where: {
          identifier_token: {
            identifier: `reset:${email}`,
            token,
          },
        },
      });

      return NextResponse.json(
        { error: "Reset link has expired. Please request a new one." },
        { status: 400 }
      );
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
      include: { password: true },
    });

    if (!user) {
      return NextResponse.json(
        { error: "User not found." },
        { status: 404 }
      );
    }

    // Hash new password
    const hash = await bcrypt.hash(password, 12);

    // Update password
    if (user.password) {
      await prisma.password.update({
        where: { userId: user.id },
        data: { hash },
      });
    } else {
      await prisma.password.create({
        data: {
          userId: user.id,
          hash,
        },
      });
    }

    // Delete reset token
    await prisma.verificationToken.delete({
      where: {
        identifier_token: {
          identifier: `reset:${email}`,
          token,
        },
      },
    });

    // Revoke all existing sessions
    await prisma.session.updateMany({
      where: {
        userId: user.id,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });

    // Audit log
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";
    await prisma.auditLog.create({
      data: {
        event: "PASSWORD_RESET",
        userId: user.id,
        ip,
        userAgent: req.headers.get("user-agent") ?? undefined,
        meta: { action: "completed" },
      },
    });

    return NextResponse.json(
      {
        success: true,
        message: "Password reset successfully. Please log in with your new password.",
      },
      { status: 200 }
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.issues[0].message },
        { status: 400 }
      );
    }

    console.error("Password reset error:", error);
    return NextResponse.json(
      { error: "An error occurred during password reset." },
      { status: 500 }
    );
  }
}

export const runtime = "nodejs";
