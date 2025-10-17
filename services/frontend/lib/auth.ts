
import { NextRequest } from "next/server";
import NextAuth, { DefaultSession } from "next-auth";
import { PrismaAdapter } from "@auth/prisma-adapter";
import CredentialsProvider from "next-auth/providers/credentials";
import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      role: "user" | "admin";
    } & DefaultSession["user"];
  }
  interface User {
    role: "user" | "admin";
  }
}

let ratelimit: Ratelimit | null = null;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  const redis = new Redis({
    url: process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.UPSTASH_REDIS_REST_TOKEN,
  });
  ratelimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(5, "10 m"),
    analytics: true,
    prefix: "auth:login",
  });
}

const credentialsSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string().optional(),
  totpToken: z.string().optional(),
});

export const { handlers, signIn, signOut, auth: nextAuth } = NextAuth({
  adapter: PrismaAdapter(prisma) as any,
  session: {
    strategy: "jwt",
    // maxAge is set dynamically per session in the callback below
    maxAge: 7 * 24 * 60 * 60, // fallback: 7 days
    updateAge: 24 * 60 * 60,
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        totpToken: { label: "TOTP Token", type: "text" },
      },
      async authorize(credentials, req) {
        try {
          const { email, password, totpToken } = credentialsSchema.parse(credentials);
          const ip = req.headers?.get("x-forwarded-for") ?? "unknown";
          
          // If TOTP token is provided, verify it and skip password check
          if (totpToken) {
            // Hash the provided token to compare with stored hash
            const crypto = await import("crypto");
            const tokenHash = crypto.createHash("sha256").update(totpToken).digest("hex");
            
            const tokenRecord = await prisma.verificationToken.findUnique({
              where: {
                identifier_token: {
                  identifier: `totp-login:${email}`,
                  token: tokenHash, // Compare hash, not plaintext
                },
              },
            });

            if (!tokenRecord || tokenRecord.expires < new Date()) {
              await prisma.auditLog.create({
                data: {
                  event: "LOGIN_FAILED",
                  ip,
                  userAgent: req.headers?.get("user-agent") ?? undefined,
                  meta: { reason: "invalid_or_expired_totp_token", email },
                },
              });
              return null;
            }

            // Delete the used token (single-use only, prevents replay attacks)
            await prisma.verificationToken.delete({
              where: {
                identifier_token: {
                  identifier: `totp-login:${email}`,
                  token: tokenHash,
                },
              },
            });

            const user = await prisma.user.findUnique({
              where: { email },
            });

            if (!user) {
              await prisma.auditLog.create({
                data: {
                  event: "LOGIN_FAILED",
                  ip,
                  userAgent: req.headers?.get("user-agent") ?? undefined,
                  meta: { reason: "user_not_found_after_totp", email },
                },
              });
              return null;
            }

            // Log successful login via TOTP
            await prisma.auditLog.create({
              data: {
                event: "LOGIN_SUCCESS",
                userId: user.id,
                ip,
                userAgent: req.headers?.get("user-agent") ?? undefined,
                meta: { method: "totp_token" },
              },
            });

            return {
              id: user.id,
              email: user.email,
              name: user.name,
              role: user.role,
              emailVerified: user.emailVerified,
            };
          }
          
          // Normal password login requires password
          if (!password) {
            return null;
          }
          
          if (ratelimit) {
            const ipLimit = await ratelimit.limit(`ip:${ip}`);
            const emailLimit = await ratelimit.limit(`email:${email}`);
            if (!ipLimit.success || !emailLimit.success) {
              await prisma.auditLog.create({
                data: {
                  event: "LOGIN_FAILED",
                  ip,
                  userAgent: req.headers?.get("user-agent") ?? undefined,
                  meta: { reason: "rate_limit", email },
                },
              });
              return null;
            }
          }
          const user = await prisma.user.findUnique({
            where: { email },
            include: { password: true },
          });
          if (!user || !user.password) {
            await prisma.auditLog.create({
              data: {
                event: "LOGIN_FAILED",
                ip,
                userAgent: req.headers?.get("user-agent") ?? undefined,
                meta: { reason: "invalid_credentials", email },
              },
            });
            return null;
          }
          const isValid = await bcrypt.compare(password, user.password.hash);
          if (!isValid) {
            await prisma.auditLog.create({
              data: {
                event: "LOGIN_FAILED",
                userId: user.id,
                ip,
                userAgent: req.headers?.get("user-agent") ?? undefined,
                meta: { reason: "invalid_password" },
              },
            });
            return null;
          }
          if (!user.emailVerified) {
            await prisma.auditLog.create({
              data: {
                event: "LOGIN_FAILED",
                userId: user.id,
                ip,
                userAgent: req.headers?.get("user-agent") ?? undefined,
                meta: { reason: "email_not_verified" },
              },
            });
            return null;
          }
          await prisma.auditLog.create({
            data: {
              event: "LOGIN_SUCCESS",
              userId: user.id,
              ip,
              userAgent: req.headers?.get("user-agent") ?? undefined,
            },
          });
          return {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            emailVerified: user.emailVerified,
          };
        } catch (error) {
          console.error("Auth error:", error);
          return null;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, trigger, session }) {
      // Store role and id
      if (user) {
        token.sub = (user as any).id ?? token.sub;
        (token as any).role = (user as any).role ?? (token as any).role ?? "user";
      }
      // Store remember flag on login
      if (trigger === "signIn" && session && typeof session.remember !== "undefined") {
        (token as any).remember = session.remember;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = (token.sub as string) ?? session.user.id;
        session.user.role = ((token as any).role as "user" | "admin") ?? "user";
      }
      // Optionally, you can expose the remember flag to the client if needed:
      // session.remember = (token as any).remember;
      return session;
    },
    async signIn({ user, account, credentials }) {
      // Only return boolean as required by NextAuth
      return true;
    },
  },
  events: {
    async signIn({ user, account, profile }) {
      if (account?.provider !== "credentials") {
        await prisma.auditLog.create({
          data: {
            event: "LOGIN_SUCCESS",
            userId: user.id,
            meta: { provider: account?.provider },
          },
        });
      }
    },
  },
  cookies: {
    sessionToken: {
      name: process.env.NODE_ENV === "production"
        ? `__Secure-next-auth.session-token`
        : `next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: "strict",
        path: "/",
        secure: process.env.NODE_ENV === "production",
      },
    },
  },
  trustHost: true,
});

export const auth = nextAuth;

export async function getSessionUser() {
  const session = await auth();
  return session?.user ?? null;
}
