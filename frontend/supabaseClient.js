// frontend/nextjs_dashboard/src/supabaseClient.ts
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = 'http://127.0.0.1:54321'; // Ihre lokale Supabase API URL
const supabaseAnonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0'; // Ihr lokaler Anon Key

export const supabase = createClient(supabaseUrl, supabaseAnonKey);