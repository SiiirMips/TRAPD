import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getSessionUser } from "@/lib/auth";

export async function GET(req: NextRequest) {
  try {
    // Get authenticated user
    const user = await getSessionUser();
    if (!user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    // Check if TOTP is verified (enabled)
    const totp = await prisma.totp.findUnique({
      where: { userId: user.id },
      select: { verified: true },
    });

    return NextResponse.json({
      enabled: totp?.verified || false,
    });
  } catch (error) {
    console.error("TOTP status check error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
