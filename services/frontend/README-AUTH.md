# TRAPD Authentication Setup

## ✅ Installation abgeschlossen

Das vollständige Auth-System für TRAPD wurde erfolgreich eingerichtet!

## 📦 Installierte Komponenten

### Datenbank & Services
- **PostgreSQL** (Port 5432) - Hauptdatenbank für User, Sessions, etc.
- **Mailpit** (Port 8025) - E-Mail Testing UI unter http://localhost:8025
- **ClickHouse** (Port 8123, 9000) - Analytics Datenbank

### Auth-Pakete
- `next-auth@5.0.0-beta.29` - Authentication Framework
- `@auth/prisma-adapter` - Prisma Integration
- `prisma` & `@prisma/client` - Database ORM
- `bcryptjs` - Password Hashing
- `zod` - Schema Validation
- `react-hook-form` - Form Handling
- `@upstash/ratelimit` - Rate Limiting
- `nodemailer` - Email Service

## 🗄️ Datenbank Schema

Das Prisma Schema beinhaltet:
- **User** - Benutzer mit Email-Verifizierung & Rollen
- **Session** - DB-basierte Sessions mit Device-Tracking
- **Account** - OAuth Provider Accounts
- **Password** - Gehashte Passwörter (bcrypt)
- **VerificationToken** - Email & Password-Reset Tokens
- **TOTP** - 2FA TOTP Secrets (vorbereitet)
- **PasskeyCredential** - WebAuthn/Passkeys (vorbereitet)
- **BackupCode** - Backup Recovery Codes (vorbereitet)
- **AuditLog** - Security Event Logging

## 🔐 Implementierte Features

### Registrierung (`/signup`)
- ✅ Email + Passwort
- ✅ Strikte Passwort-Validierung (12+ Zeichen, Groß-/Kleinbuchstaben, Zahlen, Sonderzeichen)
- ✅ Passwort-Bestätigung
- ✅ Terms & Conditions Checkbox
- ✅ Email-Verifizierung per Link
- ✅ Rate-Limiting (3 Versuche / 10 Min)
- ✅ Neutrale Fehlermeldungen (keine User-Enumeration)

### Login (`/login`)
- ✅ Email + Passwort
- ✅ NextAuth Credentials Provider
- ✅ Rate-Limiting (5 Versuche / 10 Min pro IP & Email)
- ✅ Session-basiert (DB-gespeichert)
- ✅ Device-Tracking (IP, User-Agent)
- ✅ AuditLog für Login-Versuche
- ✅ Redirect zu `/dashboard` nach Login

### Email-Verifizierung
- ✅ Token-basiert (24h Gültigkeit)
- ✅ Automatische Email nach Registrierung
- ✅ Verifizierungs-API `/api/auth/verify-email`
- ✅ E-Mails sichtbar in Mailpit UI

### Password-Reset (APIs vorbereitet)
- ✅ `/api/auth/password/reset-request` - Reset anfordern
- ✅ `/api/auth/password/reset` - Neues Passwort setzen
- ✅ Token-basiert (30 Min Gültigkeit)
- ✅ Revoke aller Sessions bei Reset
- ⏳ UI-Seiten noch zu erstellen

## 🚀 Server starten

```bash
cd services/frontend
pnpm dev
```

Server läuft auf: **http://localhost:3000**

## 🧪 Testing

### 1. Registrierung testen
1. Öffne: http://localhost:3000/signup
2. Registriere einen neuen Account
3. Öffne Mailpit UI: http://localhost:8025
4. Klicke auf den Verifizierungs-Link in der E-Mail

### 2. Login testen
1. Öffne: http://localhost:3000/login
2. Logge dich mit deinem verifizierten Account ein
3. Du wirst zu `/dashboard` weitergeleitet

### 3. Rate-Limiting testen
1. Versuche 6x mit falschem Passwort einzuloggen
2. Nach 5 Versuchen: "Too many requests"

### 4. E-Mails prüfen
- Mailpit UI: http://localhost:8025
- Alle gesendeten E-Mails werden hier angezeigt

## 📁 Wichtige Dateien

```
services/frontend/
├── .env                          # Environment Variablen
├── prisma/
│   └── schema.prisma            # Datenbank Schema
├── lib/
│   ├── auth.ts                  # NextAuth v5 Konfiguration
│   ├── email.ts                 # Email Service
│   └── prisma.ts                # Prisma Client
├── app/
│   ├── login/page.tsx           # Login Seite
│   ├── signup/page.tsx          # Signup Seite
│   └── api/auth/
│       ├── [...nextauth]/route.ts    # NextAuth Handler
│       ├── register/route.ts         # Registrierung
│       ├── verify-email/route.ts     # Email Verifizierung
│       └── password/
│           ├── reset-request/route.ts
│           └── reset/route.ts
```

## 🔧 Konfiguration

### Environment Variablen (.env)
- `DATABASE_URL` - PostgreSQL Connection String
- `NEXTAUTH_URL` - App URL (http://localhost:3000)
- `NEXTAUTH_SECRET` - Secure Random String (generiert)
- `SMTP_HOST` - Mailpit (localhost)
- `SMTP_PORT` - 1025
- `EMAIL_FROM` - Absender-Adresse

### Optional: Upstash Redis (Rate-Limiting in Production)
Für Production-Rate-Limiting:
1. Erstelle einen kostenlosen Account bei https://upstash.com
2. Erstelle eine Redis-Datenbank
3. Füge zur `.env` hinzu:
   ```
   UPSTASH_REDIS_REST_URL="https://..."
   UPSTASH_REDIS_REST_TOKEN="..."
   ```

## 🔒 Security Features

- ✅ Bcrypt Password Hashing (12 Rounds)
- ✅ Secure Session Cookies (HttpOnly, SameSite=Strict)
- ✅ Rate-Limiting (IP & Email-basiert)
- ✅ Neutrale Fehlermeldungen (keine User-Enumeration)
- ✅ Email-Verifizierung erforderlich
- ✅ Token-basierte Verifizierung (zeitlich begrenzt)
- ✅ AuditLog für Security-Events
- ✅ Session-Revoke bei Password-Reset
- ✅ CSRF-Protection (NextAuth)
- ✅ Input-Validierung (Zod)

## 🎯 Nächste Schritte

### Empfohlen:
1. **Password-Reset UI** erstellen (`/forgot-password`, `/reset`)
2. **Dashboard-Seite** erstellen (`/dashboard`)
3. **Security Middleware** für Protected Routes
4. **Session Management UI** (`/account/sessions`)
5. **2FA/TOTP** implementieren (Schema bereits vorbereitet)
6. **Passkeys/WebAuthn** implementieren (Schema bereits vorbereitet)

### Optional:
- OAuth Provider (Google, GitHub, etc.)
- Email-Template Verbesserungen
- Audit-Log Dashboard
- Admin Panel
- User Profile Management

## 📊 Datenbank-Status prüfen

```bash
# Prisma Studio öffnen (DB GUI)
cd services/frontend
pnpm exec prisma studio
```

Öffnet: http://localhost:5555

## 🐛 Troubleshooting

### Datenbank-Verbindung fehlgeschlagen
```bash
# PostgreSQL-Container prüfen
docker ps | grep postgres

# Container neu starten
docker-compose restart postgres
```

### Prisma Client Fehler
```bash
# Prisma Client neu generieren
pnpm exec prisma generate
```

### E-Mails werden nicht gesendet
```bash
# Mailpit-Container prüfen
docker ps | grep mailpit

# Container neu starten
docker-compose restart mailpit
```

## 📝 API Endpoints

| Endpoint | Method | Beschreibung |
|----------|--------|--------------|
| `/api/auth/[...nextauth]` | GET/POST | NextAuth Handler |
| `/api/auth/register` | POST | User Registration |
| `/api/auth/verify-email` | POST | Email Verification |
| `/api/auth/password/reset-request` | POST | Request Password Reset |
| `/api/auth/password/reset` | POST | Reset Password |

## ✅ Installation erfolgreich!

Das Auth-System ist jetzt vollständig funktional. Starte den Server mit `pnpm dev` und teste die Registrierung und Login-Funktionen!
