import { createClient } from '@supabase/supabase-js';

const localSupabaseUrl = 'http://127.0.0.1:54321';
const localSupabaseAnonKey =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';

const supabaseUrl =
  process.env.NEXT_PUBLIC_SUPABASE_URL ||
  (process.env.NODE_ENV === 'development' ? localSupabaseUrl : undefined);

const supabaseAnonKey =
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
  (process.env.NODE_ENV === 'development' ? localSupabaseAnonKey : undefined);

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error(
    'Supabase-Umgebungsvariablen sind nicht gesetzt. Bitte NEXT_PUBLIC_SUPABASE_URL und NEXT_PUBLIC_SUPABASE_ANON_KEY konfigurieren.'
  );
}

if (
  process.env.NODE_ENV === 'development' &&
  (!process.env.NEXT_PUBLIC_SUPABASE_URL || !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)
) {
  console.warn('Supabase verwendet lokale Fallback-Werte. Bitte Umgebungsvariablen prüfen.');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);
