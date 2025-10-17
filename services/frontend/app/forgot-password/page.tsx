"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, AlertCircle, CheckCircle2 } from "lucide-react";

type Lang = "de" | "en";
const dict: Record<Lang, any> = {
  de: {
    title: "Passwort zurücksetzen",
    description: "Wir senden dir einen Link zum Zurücksetzen.",
    email: "E-Mail",
    placeholderEmail: "du@example.com",
    submit: "Link senden",
    backToLogin: "Zurück zum Login",
    successTitle: "E-Mail (falls vorhanden) gesendet",
    successDesc: "Wenn die E-Mail existiert, erhältst du gleich einen Link zum Zurücksetzen.",
    errors: { email: "Bitte gib eine gültige E-Mail-Adresse ein", unexpected: "Es ist ein unerwarteter Fehler aufgetreten. Bitte versuche es erneut." },
  },
  en: {
    title: "Reset password",
    description: "We'll send you a reset link.",
    email: "Email",
    placeholderEmail: "you@example.com",
    submit: "Send link",
    backToLogin: "Back to login",
    successTitle: "Email (if exists) sent",
    successDesc: "If the email exists, you'll receive a link to reset shortly.",
    errors: { email: "Please enter a valid email address", unexpected: "An unexpected error occurred. Please try again." },
  },
};

const schema = (lang: Lang) => z.object({ email: z.string().email(dict[lang].errors.email).toLowerCase().trim() });

type FormData = z.infer<ReturnType<typeof schema>>;

export default function ForgotPasswordPage() {
  const [lang, setLang] = useState<Lang>("de");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("trapd-lang") : null;
    if (stored === "de" || stored === "en") setLang(stored);
  }, []);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<FormData>({ resolver: zodResolver(schema(lang)) });

  const onSubmit = async (data: FormData) => {
    setIsLoading(true);
    setError("");
    try {
      const res = await fetch("/api/auth/password/reset-request", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: data.email }) });
      await res.json();
      setSuccess(true);
    } catch (e) {
      setError(dict[lang].errors.unexpected);
    } finally {
      setIsLoading(false);
    }
  };

  if (success) {
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
    )
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
                <clipPath id="s2"><path d="M0,0 v30 h60 v-30 z"/></clipPath>
                <clipPath id="t2"><path d="M30,15 h30 v15 z v-15 h-30 z h-30 v15 z v-15 h30 z"/></clipPath>
                <g clipPath="url(#s2)">
                  <path d="M0,0 v30 h60 v-30 z" fill="#012169"/>
                  <path d="M0,0 L60,30 M60,0 L0,30" stroke="#fff" strokeWidth="6"/>
                  <path d="M0,0 L60,30 M60,0 L0,30" clipPath="url(#t2)" stroke="#C8102E" strokeWidth="4"/>
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
                  <FieldLabel htmlFor="email">{dict[lang].email}</FieldLabel>
                  <Input id="email" type="email" placeholder={dict[lang].placeholderEmail} autoComplete="email" disabled={isLoading} {...register("email")} />
                  {errors.email && (<p className="text-sm text-red-500">{errors.email.message}</p>)}
                </Field>
                <Field>
                  <Button type="submit" className="w-full" disabled={isLoading}>{isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}{dict[lang].submit}</Button>
                  <FieldDescription className="text-center"><Link href="/login" className="underline">{dict[lang].backToLogin}</Link></FieldDescription>
                </Field>
              </FieldGroup>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
