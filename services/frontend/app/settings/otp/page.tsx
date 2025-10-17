"use client";
import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Input } from "@/components/ui/input";
import { Field, FieldLabel } from "@/components/ui/field";
import { CheckCircle2, Copy, AlertTriangle } from "lucide-react";

export default function OTPSettingsPage() {
  const [otpauth, setOtpauth] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [totpEnabled, setTotpEnabled] = useState(false);
  const [password, setPassword] = useState("");
  const [checkingStatus, setCheckingStatus] = useState(true);

  async function handleSetup() {
    setLoading(true);
    setError(null);
    setSuccess(false);
    try {
      const res = await fetch("/api/auth/totp/setup", { method: "POST" });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Setup failed");
      } else {
        setOtpauth(data.otpauth);
      }
    } catch (err) {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);
    try {
      const res = await fetch("/api/auth/totp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Verification failed");
      } else {
        setSuccess(true);
        setBackupCodes(data.backupCodes || []);
        setTotpEnabled(true);
      }
    } catch (err) {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }

  async function handleDisable(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/auth/totp/disable", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Failed to disable TOTP");
      } else {
        setTotpEnabled(false);
        setOtpauth(null);
        setPassword("");
      }
    } catch (err) {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }

  async function checkTotpStatus() {
    try {
      const res = await fetch("/api/auth/totp/status");
      if (res.ok) {
        const data = await res.json();
        setTotpEnabled(data.enabled || false);
      }
    } catch (err) {
      console.error("Failed to check TOTP status");
    } finally {
      setCheckingStatus(false);
    }
  }

  useEffect(() => {
    checkTotpStatus();
  }, []);

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
  }

  if (checkingStatus) {
    return (
      <div className="max-w-md mx-auto mt-10">
        <Card>
          <CardContent className="pt-6 text-center">Lade...</CardContent>
        </Card>
      </div>
    );
  }

  if (backupCodes.length > 0) {
    return (
      <div className="max-w-md mx-auto mt-10">
        <Card>
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900">
              <CheckCircle2 className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <CardTitle>TOTP erfolgreich aktiviert!</CardTitle>
            <CardDescription>Speichere diese Backup-Codes sicher</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="mb-4 p-4 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-lg">
              <div className="flex items-start gap-2 text-sm text-amber-800 dark:text-amber-200">
                <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <div>
                  Diese Codes werden nur einmal angezeigt! Speichere sie an einem sicheren Ort.
                  Du kannst sie verwenden, wenn du keinen Zugriff auf deine Authenticator App hast.
                </div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 mb-4">
              {backupCodes.map((code, i) => (
                <div key={i} className="flex items-center gap-2 p-2 bg-muted rounded font-mono text-sm">
                  <span className="flex-1">{code}</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(code)}
                    className="p-1 hover:bg-background rounded"
                  >
                    <Copy className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
            <Button
              onClick={() => {
                copyToClipboard(backupCodes.join("\n"));
              }}
              variant="outline"
              className="w-full mb-2"
            >
              Alle Codes kopieren
            </Button>
            <Button onClick={() => window.location.reload()} className="w-full">
              Fertig
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (totpEnabled) {
    return (
      <div className="max-w-md mx-auto mt-10">
        <Card>
          <CardHeader>
            <CardTitle>TOTP ist aktiviert</CardTitle>
            <CardDescription>
              Zwei-Faktor-Authentifizierung ist für dein Konto aktiv
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="mb-4 p-4 bg-green-50 dark:bg-green-950 border border-green-200 dark:border-green-800 rounded-lg">
              <div className="flex items-center gap-2 text-sm text-green-800 dark:text-green-200">
                <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
                <div>Dein Konto ist durch TOTP 2FA geschützt</div>
              </div>
            </div>
            <form onSubmit={handleDisable} className="space-y-4">
              <Field>
                <FieldLabel htmlFor="password">Passwort zur Bestätigung</FieldLabel>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Gib dein Passwort ein"
                  required
                />
              </Field>
              {error && (
                <div className="text-sm text-destructive">{error}</div>
              )}
              <Button
                type="submit"
                variant="destructive"
                className="w-full"
                disabled={loading || !password}
              >
                {loading ? "Deaktiviere..." : "TOTP deaktivieren"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-md mx-auto mt-10">
      <Card>
        <CardHeader>
          <CardTitle>TOTP Zwei-Faktor-Authentifizierung</CardTitle>
          <CardDescription>
            Richte die Anmeldung mit einer Authenticator App ein (z.B. Google Authenticator, Authy).
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!otpauth ? (
            <Button onClick={handleSetup} disabled={loading}>
              {loading ? "Lade..." : "TOTP Setup starten"}
            </Button>
          ) : (
            <>
              <div className="mb-4 text-center">
                <div className="mb-2 text-sm font-medium">1. QR-Code scannen</div>
                <div className="mb-2 text-xs text-muted-foreground">
                  Scanne diesen Code mit deiner Authenticator App
                </div>
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(otpauth)}&size=200x200`}
                  alt="QR Code"
                  className="mx-auto border rounded-lg p-2"
                />
                <details className="mt-4">
                  <summary className="text-xs text-muted-foreground cursor-pointer">
                    Manuelle Eingabe anzeigen
                  </summary>
                  <div className="mt-2 break-all text-xs font-mono bg-muted p-2 rounded">
                    {otpauth}
                  </div>
                </details>
              </div>
              <form onSubmit={handleVerify} className="space-y-4">
                <div>
                  <div className="mb-2 text-sm font-medium">2. Code eingeben</div>
                  <div className="mb-2 text-xs text-muted-foreground">
                    Gib den 6-stelligen Code aus deiner App ein
                  </div>
                  <InputOTP
                    maxLength={6}
                    id="otp"
                    required
                    value={code}
                    onChange={setCode}
                  >
                    <InputOTPGroup className="gap-2.5 *:data-[slot=input-otp-slot]:rounded-md *:data-[slot=input-otp-slot]:border">
                      {[0, 1, 2, 3, 4, 5].map((i) => (
                        <InputOTPSlot key={i} index={i} />
                      ))}
                    </InputOTPGroup>
                  </InputOTP>
                </div>
                {error && (
                  <div className="text-sm text-destructive text-center">{error}</div>
                )}
                <Button
                  type="submit"
                  disabled={loading || code.length !== 6}
                  className="w-full"
                >
                  {loading ? "Prüfe..." : "Verifizieren & Aktivieren"}
                </Button>
              </form>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
