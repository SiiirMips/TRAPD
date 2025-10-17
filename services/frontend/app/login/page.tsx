"use client";

import { useEffect, useMemo, useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle } from "lucide-react";
type Lang = "de" | "en";

const dict: Record<Lang, any> = {
  de: {
    title: "Willkommen zurück",
    description: "Melde dich bei deinem TRAPD Konto an",
    email: "E-Mail",
    password: "Passwort",
    placeholderEmail: "du@example.com",
    placeholderPassword: "Gib dein Passwort ein",
    forgot: "Passwort vergessen?",
    signin: "Anmelden",
    signupQ: "Noch kein Konto?",
    signup: "Registrieren",
    errors: {
      email: "Bitte gib eine gültige E-Mail-Adresse ein",
      passwordRequired: "Passwort ist erforderlich",
      invalidCredentials: "Ungültige Zugangsdaten. Bitte prüfe E-Mail und Passwort.",
      unexpected: "Es ist ein unerwarteter Fehler aufgetreten. Bitte versuche es erneut.",
    },
  },
  en: {
    title: "Welcome back",
    description: "Sign in to your TRAPD account",
    email: "Email",
    password: "Password",
    placeholderEmail: "you@example.com",
    placeholderPassword: "Enter your password",
    forgot: "Forgot password?",
    signin: "Sign in",
    signupQ: "Don't have an account?",
    signup: "Sign up",
    errors: {
      email: "Please enter a valid email address",
      passwordRequired: "Password is required",
      invalidCredentials: "Invalid credentials. Please check your email and password.",
      unexpected: "An unexpected error occurred. Please try again.",
    },
  },
};

type LoginFormData = { email: string; password: string; remember?: boolean };

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const emailParam = searchParams?.get("email") ?? "";
  const [lang, setLang] = useState<Lang>("de");
  const [error, setError] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("trapd-lang") : null;
    if (stored === "de" || stored === "en") setLang(stored);
  }, []);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(
      z.object({
        email: z.string().email(dict[lang].errors.email).toLowerCase().trim(),
        password: z.string().min(1, dict[lang].errors.passwordRequired),
        remember: z.boolean().optional(),
      })
    ),
    defaultValues: { email: emailParam, remember: false },
  });

  const onSubmit = async (data: LoginFormData) => {
    setIsLoading(true);
    setError("");

    try {
      // First check if TOTP is required
      const checkRes = await fetch("/api/auth/login-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: data.email,
          password: data.password,
        }),
      });

      const checkData = await checkRes.json();

      if (!checkRes.ok) {
        if (checkData.requiresVerification) {
          setError("Please verify your email first.");
        } else {
          setError(dict[lang].errors.invalidCredentials);
        }
        setIsLoading(false);
        return;
      }

      // If TOTP is required, redirect to TOTP page
      if (checkData.requiresTotp) {
        router.push(
          `/totp-login?userId=${encodeURIComponent(checkData.userId)}&email=${encodeURIComponent(data.email)}`
        );
        return;
      }

      // Otherwise, proceed with normal login
      const result = await signIn("credentials", {
        redirect: false,
        email: data.email,
        password: data.password,
        remember: data.remember,
      });

      if (result?.error) {
        setError(dict[lang].errors.invalidCredentials);
      } else if (result?.ok) {
        router.push("/dashboard");
        router.refresh();
      }
    } catch (err) {
      setError(dict[lang].errors.unexpected);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <a href="/" className="flex items-center justify-center gap-2 self-center font-medium">
          <h1 className="text-2xl font-bold tracking-tight">TRAPD</h1>
        </a>
        
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="text-xl">{dict[lang].title}</CardTitle>
            <CardDescription>{dict[lang].description}</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)}>
              <FieldGroup>
                {error && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}

                <Field>
                  <FieldLabel htmlFor="email">{dict[lang].email}</FieldLabel>
                  <Input
                    id="email"
                    type="email"
                    placeholder={dict[lang].placeholderEmail}
                    autoComplete="email"
                    disabled={isLoading}
                    {...register("email")}
                  />
                  {errors.email && (
                    <p className="text-sm text-red-500">{errors.email.message}</p>
                  )}
                </Field>

                <Field>
                  <div className="flex items-center">
                    <FieldLabel htmlFor="password">{dict[lang].password}</FieldLabel>
                    <Link
                      href="/forgot-password"
                      className="ml-auto text-sm underline-offset-4 hover:underline"
                    >
                      {dict[lang].forgot}
                    </Link>
                  </div>
                  <Input
                    id="password"
                    type="password"
                    placeholder={dict[lang].placeholderPassword}
                    autoComplete="current-password"
                    disabled={isLoading}
                    {...register("password")}
                  />
                  {errors.password && (
                    <p className="text-sm text-red-500">{errors.password.message}</p>
                  )}
                </Field>

                <Field>
                  <div className="flex items-center gap-2 mb-2">
                    <input
                      id="remember"
                      type="checkbox"
                      className="h-4 w-4 rounded border-gray-300"
                      disabled={isLoading}
                      {...register("remember")}
                    />
                    <label htmlFor="remember" className="text-sm text-muted-foreground select-none">
                      Angemeldet bleiben
                    </label>
                  </div>
                  <Button type="submit" className="w-full" disabled={isLoading}>
                    {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    {dict[lang].signin}
                  </Button>
                  <FieldDescription className="text-center">
                    {dict[lang].signupQ}{" "}
                    <Link href="/signup" className="underline">
                      {dict[lang].signup}
                    </Link>
                  </FieldDescription>
                </Field>
              </FieldGroup>
            </form>
            <div className="mt-4 flex items-center justify-start">
              <div className="inline-flex items-center gap-1 rounded-md border bg-muted/30 p-1">
                <button
                  type="button"
                  onClick={() => { setLang("de"); if (typeof window !== "undefined") localStorage.setItem("trapd-lang", "de"); }}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded transition-colors ${lang === "de" ? "bg-background font-medium shadow-sm" : "opacity-60 hover:opacity-100"}`}
                  aria-label="Deutsch"
                >
                  <svg className="w-4 h-3" viewBox="0 0 5 3" xmlns="http://www.w3.org/2000/svg">
                    <rect width="5" height="3" fill="#000"/>
                    <rect width="5" height="2" y="1" fill="#D00"/>
                    <rect width="5" height="1" y="2" fill="#FFCE00"/>
                  </svg>
                  <span>DE</span>
                </button>
                <button
                  type="button"
                  onClick={() => { setLang("en"); if (typeof window !== "undefined") localStorage.setItem("trapd-lang", "en"); }}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded transition-colors ${lang === "en" ? "bg-background font-medium shadow-sm" : "opacity-60 hover:opacity-100"}`}
                  aria-label="English"
                >
                  <svg className="w-4 h-3" viewBox="0 0 60 30" xmlns="http://www.w3.org/2000/svg">
                    <clipPath id="s"><path d="M0,0 v30 h60 v-30 z"/></clipPath>
                    <clipPath id="t"><path d="M30,15 h30 v15 z v-15 h-30 z h-30 v15 z v-15 h30 z"/></clipPath>
                    <g clipPath="url(#s)">
                      <path d="M0,0 v30 h60 v-30 z" fill="#012169"/>
                      <path d="M0,0 L60,30 M60,0 L0,30" stroke="#fff" strokeWidth="6"/>
                      <path d="M0,0 L60,30 M60,0 L0,30" clipPath="url(#t)" stroke="#C8102E" strokeWidth="4"/>
                      <path d="M30,0 v30 M0,15 h60" stroke="#fff" strokeWidth="10"/>
                      <path d="M30,0 v30 M0,15 h60" stroke="#C8102E" strokeWidth="6"/>
                    </g>
                  </svg>
                  <span>EN</span>
                </button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
