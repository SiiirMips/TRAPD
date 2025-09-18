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
