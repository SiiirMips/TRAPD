import NextAuth, { DefaultSession } from "next-auth";
import { PrismaAdapter } from "@auth/prisma-adapter";
import CredentialsProvider from "next-auth/providers/credentials";
import { prisma } from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Extend NextAuth types
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

// Rate limiter setup (fallback to memory if Upstash not configured)
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

// Validation schemas
const credentialsSchema = z.object({
  email: z.string().email().toLowerCase().trim(),
  password: z.string().min(1),
});

export const { handlers, signIn, signOut, auth } = NextAuth({
  adapter: PrismaAdapter(prisma) as any,
  session: {
    // Credentials in Auth.js v5 require JWT strategy
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
    updateAge: 24 * 60 * 60, // 24 hours
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
      },
      async authorize(credentials, req) {
        try {
          // Validate input
          const { email, password } = credentialsSchema.parse(credentials);

          // Rate limit check (by IP and email)
          const ip = req.headers?.get("x-forwarded-for") ?? "unknown";
          
          if (ratelimit) {
            const ipLimit = await ratelimit.limit(`ip:${ip}`);
            const emailLimit = await ratelimit.limit(`email:${email}`);

            if (!ipLimit.success || !emailLimit.success) {
              // Log failed attempt
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

          // Find user with password
          const user = await prisma.user.findUnique({
            where: { email },
            include: { password: true },
          });

          // Neutral response for security (no user enumeration)
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

          // Verify password
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

          // Check email verification
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

          // Success - log it
          await prisma.auditLog.create({
            data: {
              event: "LOGIN_SUCCESS",
              userId: user.id,
              ip,
              userAgent: req.headers?.get("user-agent") ?? undefined,
            },
          });

          // Return user (without password)
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
    async jwt({ token, user }) {
      // On initial sign-in, persist user id and role into the token
      if (user) {
        token.sub = (user as any).id ?? token.sub;
        (token as any).role = (user as any).role ?? (token as any).role ?? "user";
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        // token.sub contains user id
        session.user.id = (token.sub as string) ?? session.user.id;
        // custom role propagated via token
        session.user.role = ((token as any).role as "user" | "admin") ?? "user";
      }
      return session;
    },
    async signIn({ user, account }) {
      // Additional checks can be added here
      return true;
    },
  },
  events: {
    async signIn({ user, account, profile }) {
      // Already logged in authorize, but log OAuth if added later
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
      name: `__Secure-next-auth.session-token`,
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
