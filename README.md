# Dein Projektname (Platzhalter)

**Ein innovatives, KI-gesteuertes Täuschungssystem (Arbeitstitel)**

Dies ist ein Projekt, das darauf abzielt, Angreifer in Honeypot-Umgebungen nicht nur zu erkennen, sondern sie gezielt mit widersprüchlichen und irreführenden Informationen zu versorgen. Das primäre Ziel ist es, die digitalen Fingerabdrücke der Angreifer zu verunreinigen, ihre Taktiken (TTPs) zu stören und sie zu verwirren, während gleichzeitig tiefgehende, anonymisierte Erkenntnisse über ihre wahre Identität und ihr Netzwerk gesammelt werden. Es transformiert den passiven Honeypot in ein dynamisches Täuschungssystem, das aktiv die Aufklärungsphase eines Angreifers manipuliert.

---

## Inhaltsverzeichnis
- [Projektbeschreibung](#projektbeschreibung)
- [Kernprobleme & Lösungen](#kernprobleme--lösungen)
- [Tech Stack](#tech-stack)
- [Getting Started (MVP)](#getting-started-mvp)
- [Contributing](#contributing)

---

## Projektbeschreibung
[Die detailliertere Beschreibung des Projekts wird hier eingefügt, sobald der endgültige Name und die Ausrichtung feststehen.]

---

## Kernprobleme & Lösungen
Herkömmliche Honeypots sind primär darauf ausgelegt, Angreifer anzulocken und ihre Aktionen zu protokollieren. Sie bieten jedoch wenig Möglichkeiten, die Identität hinter dem Angriff zu dekonstruieren oder den Angreifer selbst zu desorientieren. Dieses Projekt schließt diese Lücke, indem es eine kontinuierliche Desinformationsschleife erzeugt, die Angreifer dazu verleitet, ihre Tools, Daten und Kommunikationswege zu offenbaren und dabei inkonsistente Informationen zu verbreiten.

---

## Tech Stack
* **Rust:** Hochperformanter Kern für Honeypot-Module und Daten-Ingestion.
* **Python:** Herzstück der KI-Engine (NLG, Verhaltensanalyse, Datenkorrelation).
* **Next.js (TypeScript):** Interaktives Web-Dashboard.
* **Supabase (PostgreSQL mit Vector-Datenbank-Erweiterungen):** Backend für Angreiferprofile, Desinformation, Logs und Wissensbasis.

---

## Getting Started (MVP)
Um das MVP lokal zu starten, folge diesen Schritten:

1.  **Voraussetzungen installieren:**
    * [Docker Desktop](https://www.docker.com/products/docker-desktop/) (für Supabase)
    * [Rust](https://www.rust-lang.org/tools/install)
    * [Python 3.x](https://www.python.org/downloads/)
    * [Node.js & npm](https://nodejs.org/en/download/) (für Next.js)
    * [Supabase CLI](https://supabase.com/docs/guides/cli) (siehe Installationsanleitung in der docs/dev_setup.md)

2.  **Lokale Supabase-Instanz starten:**
    `ash
    cd backend/supabase
    supabase init
    supabase start
    `
    Notiere dir die lokalen URLs und Keys, die Supabase ausgibt.

3.  **Datenbankmigration anwenden:**
    `ash
    cd backend/supabase
    supabase migration new initial_schema # Erstellt eine neue Migrationsdatei
    # Füge dein SQL-Schema in die neu erstellte Datei ein (z.B. backend/supabase/migrations/xxxx_initial_schema.sql)
    # Beispiel-SQL für 'attacker_logs' und 'disinformation_content' ist in der docs/dev_setup.md
    supabase db reset # Wendet alle Migrationen an und seedet optional Daten
    `

4.  **Rust Honeypots kompilieren und starten:**
    `ash
    cd backend/rust_honeypots
    cargo build
    cargo run # Oder führe die kompilierte Binary direkt aus
    `

5.  **Python AI starten:**
    `ash
    cd backend/python_ai
    python -m venv venv
    .\venv\Scripts\Activate.ps1 # Für Windows PowerShell
    # source venv/bin/activate # Für Linux/macOS Bash
    pip install -r requirements.txt
    python src/main.py
    `

6.  **Next.js Dashboard starten:**
    `ash
    cd frontend/nextjs_dashboard
    npm install
    npm run dev
    `

Du solltest nun auf http://localhost:3000 dein Dashboard erreichen und die Backend-Dienste laufen haben.

---

## Contributing
Dieses Projekt ist Open Source. Beiträge sind willkommen! Bitte lies die CONTRIBUTING.md (wird noch erstellt) für Details zum Beitragsprozess.
