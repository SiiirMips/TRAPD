"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle, CheckCircle2, XCircle } from "lucide-react";

type Lang = "de" | "en";
const dict: Record<Lang, any> = {
  de: {
    title: "Neues Passwort setzen",
    description: "Gib ein starkes neues Passwort ein.",
    password: "Neues Passwort",
    confirm: "Passwort bestätigen",
    placeholderPassword: "Neues Passwort",
    submit: "Passwort ändern",
    backToLogin: "Zurück zum Login",
    successTitle: "Passwort geändert",
    successDesc: "Du kannst dich jetzt mit deinem neuen Passwort anmelden.",
    errors: {
      pwdLen: "Mindestens 12 Zeichen",
      lower: "Ein Kleinbuchstabe erforderlich",
      upper: "Ein Großbuchstabe erforderlich",
      num: "Eine Zahl erforderlich",
      special: "Ein Sonderzeichen erforderlich",
      mismatch: "Passwörter stimmen nicht überein",
      unexpected: "Es ist ein unerwarteter Fehler aufgetreten. Bitte versuche es erneut.",
    },
  },
  en: {
    title: "Set a new password",
    description: "Enter a strong new password.",
    password: "New password",
    confirm: "Confirm password",
    placeholderPassword: "New password",
    submit: "Change password",
    backToLogin: "Back to login",
    successTitle: "Password changed",
    successDesc: "You can now sign in with your new password.",
    errors: {
      pwdLen: "At least 12 characters",
      lower: "Must contain a lowercase letter",
      upper: "Must contain an uppercase letter",
      num: "Must contain a number",
      special: "Must contain a special character",
      mismatch: "Passwords do not match",
      unexpected: "An unexpected error occurred. Please try again.",
    },
  },
};

const passwordSchema = (lang: Lang) => z.object({
  password: z.string()
    .min(12, dict[lang].errors.pwdLen)
    .regex(/[a-z]/, dict[lang].errors.lower)
    .regex(/[A-Z]/, dict[lang].errors.upper)
    .regex(/[0-9]/, dict[lang].errors.num)
    .regex(/[^a-zA-Z0-9]/, dict[lang].errors.special),
  confirmPassword: z.string(),
}).refine((d) => d.password === d.confirmPassword, { message: dict[lang].errors.mismatch, path: ["confirmPassword"] });

type FormData = z.infer<ReturnType<typeof passwordSchema>>;

export default function ResetPage() {
  const router = useRouter();
  const sp = useSearchParams();
  const [lang, setLang] = useState<Lang>("de");
  const [status, setStatus] = useState<"form" | "success" | "error">("form");
  const [error, setError] = useState("");

  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("trapd-lang") : null;
    if (stored === "de" || stored === "en") setLang(stored);
  }, []);

  const email = sp.get("email");
  const token = sp.get("token");

  const { register, handleSubmit, formState: { errors }, } = useForm<FormData>({ resolver: zodResolver(passwordSchema(lang)) });

  const onSubmit = async (data: FormData) => {
    if (!email || !token) { setStatus("error"); setError("Invalid link"); return; }
    try {
      const res = await fetch("/api/auth/password/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, token, password: data.password }) });
      const json = await res.json();
      if (!res.ok) {
        setStatus("error");
        setError(json.error || dict[lang].errors.unexpected);
        return;
      }
      setStatus("success");
    } catch (e) {
      setStatus("error");
      setError(dict[lang].errors.unexpected);
    }
  };

  if (status === "success") {
    return (
      <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 md:p-10">
        <div className="flex w-full max-w-sm flex-col gap-6">
          <a href="/" className="flex items-center justify-center gap-2 self-center font-medium"><h1 className="text-2xl font-bold tracking-tight">TRAPD</h1></a>
          <Card>
            <CardHeader className="text-center">
              <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900"><CheckCircle2 className="h-6 w-6 text-green-600 dark:text-green-400" /></div>
              <CardTitle className="text-xl">{dict[lang].successTitle}</CardTitle>
              <CardDescription>{dict[lang].successDesc}</CardDescription>
            </CardHeader>
            <CardContent>
              <Button variant="outline" className="w-full" asChild><Link href="/login">{dict[lang].backToLogin}</Link></Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <div className="flex justify-end">
          <div className="inline-flex items-center gap-1 rounded-md border bg-background p-1 shadow-sm">
            <button type="button" onClick={() => { setLang("de"); localStorage.setItem("trapd-lang", "de"); }} className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded transition-colors ${lang === "de" ? "bg-muted font-medium" : "opacity-70"}`} aria-label="Deutsch">
              <svg className="w-4 h-3" viewBox="0 0 5 3" xmlns="http://www.w3.org/2000/svg">
                <rect width="5" height="3" fill="#000"/>
                <rect width="5" height="2" y="1" fill="#D00"/>
                <rect width="5" height="1" y="2" fill="#FFCE00"/>
              </svg>
              <span>DE</span>
            </button>
            <button type="button" onClick={() => { setLang("en"); localStorage.setItem("trapd-lang", "en"); }} className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded transition-colors ${lang === "en" ? "bg-muted font-medium" : "opacity-70"}`} aria-label="English">
              <svg className="w-4 h-3" viewBox="0 0 60 30" xmlns="http://www.w3.org/2000/svg">
                <clipPath id="s3"><path d="M0,0 v30 h60 v-30 z"/></clipPath>
                <clipPath id="t3"><path d="M30,15 h30 v15 z v-15 h-30 z h-30 v15 z v-15 h30 z"/></clipPath>
                <g clipPath="url(#s3)">
                  <path d="M0,0 v30 h60 v-30 z" fill="#012169"/>
                  <path d="M0,0 L60,30 M60,0 L0,30" stroke="#fff" strokeWidth="6"/>
                  <path d="M0,0 L60,30 M60,0 L0,30" clipPath="url(#t3)" stroke="#C8102E" strokeWidth="4"/>
                  <path d="M30,0 v30 M0,15 h60" stroke="#fff" strokeWidth="10"/>
                  <path d="M30,0 v30 M0,15 h60" stroke="#C8102E" strokeWidth="6"/>
                </g>
              </svg>
              <span>EN</span>
            </button>
          </div>
        </div>
        <a href="/" className="flex items-center justify-center gap-2 self-center font-medium"><h1 className="text-2xl font-bold tracking-tight">TRAPD</h1></a>
        <Card>
          <CardHeader className="text-center">
            <CardTitle className="text-xl">{dict[lang].title}</CardTitle>
            <CardDescription>{dict[lang].description}</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)}>
              <FieldGroup>
                {error && (<Alert variant="destructive"><AlertCircle className="h-4 w-4" /><AlertDescription>{error}</AlertDescription></Alert>)}
                <Field>
                  <FieldLabel htmlFor="password">{dict[lang].password}</FieldLabel>
                  <Input id="password" type="password" placeholder={dict[lang].placeholderPassword} autoComplete="new-password" {...register("password")} />
                  {errors.password && (<p className="text-sm text-red-500">{errors.password.message}</p>)}
                </Field>
                <Field>
                  <FieldLabel htmlFor="confirmPassword">{dict[lang].confirm}</FieldLabel>
                  <Input id="confirmPassword" type="password" placeholder={dict[lang].placeholderPassword} autoComplete="new-password" {...register("confirmPassword")} />
                  {errors.confirmPassword && (<p className="text-sm text-red-500">{errors.confirmPassword.message}</p>)}
                </Field>
                <Field>
                  <Button type="submit" className="w-full" disabled={false}>{<Loader2 className="mr-2 h-4 w-4 hidden" />}{dict[lang].submit}</Button>
                </Field>
              </FieldGroup>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
