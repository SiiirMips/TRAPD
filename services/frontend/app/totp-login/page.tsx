"use client";

import { useState, useEffect } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Field, FieldLabel, FieldDescription } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Loader2, AlertCircle, ShieldCheck } from "lucide-react";

export default function TotpLoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const userId = searchParams?.get("userId");
  const email = searchParams?.get("email");

  const [code, setCode] = useState("");
  const [error, setError] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);
  const [useBackup, setUseBackup] = useState(false);
  const [backupCode, setBackupCode] = useState("");

  useEffect(() => {
    if (!userId) {
      router.push("/login");
    }
  }, [userId, router]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userId) return;

    setIsLoading(true);
    setError("");

    try {
      const verificationCode = useBackup ? backupCode : code;
      
      // Verify TOTP/Backup code
      const res = await fetch("/api/auth/totp/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId,
          code: verificationCode,
          useBackup,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Verification failed");
        setIsLoading(false);
        return;
      }

      // TOTP verified successfully - complete login with the token
      const result = await signIn("credentials", {
        redirect: false,
        email: email || "",
        password: "", // Not needed with token
        totpToken: data.loginToken,
      });

      if (result?.ok) {
        router.push("/dashboard");
        router.refresh();
      } else {
        setError("Login completion failed. Please try again.");
      }
    } catch (err) {
      setError("An unexpected error occurred.");
    } finally {
      setIsLoading(false);
    }
  };

  if (!userId) {
    return null;
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-6 bg-muted p-6 md:p-10">
      <div className="flex w-full max-w-sm flex-col gap-6">
        <a href="/" className="flex items-center justify-center gap-2 self-center font-medium">
          <h1 className="text-2xl font-bold tracking-tight">TRAPD</h1>
        </a>

        <Card>
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <ShieldCheck className="h-6 w-6 text-primary" />
            </div>
            <CardTitle className="text-xl">Zwei-Faktor-Authentifizierung</CardTitle>
            <CardDescription>
              {useBackup
                ? "Gib einen deiner Backup-Codes ein"
                : "Gib den 6-stelligen Code aus deiner Authenticator App ein"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleVerify} className="space-y-4">
              {error && (
                <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200">
                  <AlertCircle className="h-4 w-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {!useBackup ? (
                <Field>
                  <FieldLabel htmlFor="totp">Authenticator Code</FieldLabel>
                  <InputOTP
                    maxLength={6}
                    id="totp"
                    required
                    value={code}
                    onChange={setCode}
                    disabled={isLoading}
                  >
                    <InputOTPGroup className="gap-2.5 *:data-[slot=input-otp-slot]:rounded-md *:data-[slot=input-otp-slot]:border">
                      {[0, 1, 2, 3, 4, 5].map((i) => (
                        <InputOTPSlot key={i} index={i} />
                      ))}
                    </InputOTPGroup>
                  </InputOTP>
                </Field>
              ) : (
                <Field>
                  <FieldLabel htmlFor="backup">Backup Code</FieldLabel>
                  <Input
                    id="backup"
                    type="text"
                    placeholder="XXXXXXXX"
                    value={backupCode}
                    onChange={(e) => setBackupCode(e.target.value.toUpperCase())}
                    disabled={isLoading}
                    maxLength={8}
                    required
                  />
                  <FieldDescription>
                    8-stelliger Backup-Code (z.B. A1B2C3D4)
                  </FieldDescription>
                </Field>
              )}

              <Button
                type="submit"
                className="w-full"
                disabled={
                  isLoading ||
                  (!useBackup && code.length !== 6) ||
                  (useBackup && backupCode.length !== 8)
                }
              >
                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Verifizieren
              </Button>

              <button
                type="button"
                onClick={() => {
                  setUseBackup(!useBackup);
                  setCode("");
                  setBackupCode("");
                  setError("");
                }}
                className="w-full text-sm text-muted-foreground hover:text-foreground underline-offset-4 hover:underline"
                disabled={isLoading}
              >
                {useBackup
                  ? "Authenticator App verwenden"
                  : "Backup-Code verwenden"}
              </button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
