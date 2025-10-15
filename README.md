# TRAPD

## Next.js-Frontend konfigurieren

Das Frontend im Ordner `frontend` nutzt Supabase. Damit die Anwendung sowohl lokal als auch in einer Deployment-Umgebung funktioniert, müssen die folgenden Umgebungsvariablen gesetzt werden:

- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`

### Schritt-für-Schritt

1. Wechsle in den Frontend-Ordner und installiere die Abhängigkeiten:
   ```bash
   cd frontend
   npm install
   ```
2. Kopiere die Beispieldatei `.env.example` zu `.env.local` (wird von Next.js automatisch eingelesen):
   ```bash
   cp .env.example .env.local
   ```
3. Passe die Werte in `.env.local` an deine Supabase-Instanz an:
   - Für die lokale Entwicklung kannst du die mitgelieferten Beispielwerte verwenden.
   - Für andere Umgebungen (z. B. Vercel) trägst du die URL und den Anon-Key deiner gehosteten Supabase-Instanz ein. Lege die Variablen dort in den jeweiligen Build-Einstellungen an.

> Hinweis: Der Supabase Service-Role-Key wird nicht clientseitig verwendet. Sollte zukünftig eine Operation den Service-Role-Key benötigen, muss sie in eine sichere Next.js API-Route ausgelagert werden.

### Build prüfen

Mit gesetzten Variablen kann der Production-Build getestet werden:

```bash
NEXT_PUBLIC_SUPABASE_URL=https://deine-supabase-url.supabase.co \
NEXT_PUBLIC_SUPABASE_ANON_KEY=dein-anon-key \
npm run build
```

Für die lokale Entwicklung (`npm run dev`) greift das Frontend automatisch auf die lokalen Supabase-Fallback-Werte zurück, falls die Variablen nicht gesetzt sind.

## Alle Services auf einmal starten

Im Projektwurzelverzeichnis steht jetzt ein Skript `./start_all.sh` bereit, das auf Wunsch alle relevanten Komponenten für die lokale Entwicklung hochfährt:

```bash
./start_all.sh
```

Das Skript versucht dabei automatisch folgende Dienste zu starten (sofern die benötigten Abhängigkeiten installiert sind):

- Supabase (per `supabase start` – benötigt die [Supabase CLI](https://supabase.com/docs/guides/cli))
- Python KI-Backend (`backend/python_ai`, via `uvicorn`)
- Rust Honeypots (`backend/rust_honeypots`, via `cargo`)
- Next.js Frontend (`frontend`, via `npm run dev`)

Über optionale Parameter können einzelne Komponenten ausgelassen werden, z. B. `./start_all.sh --skip-supabase --skip-rust`. Beim Beenden des Skripts (z. B. per `Strg+C`) werden alle gestarteten Prozesse kontrolliert gestoppt.
