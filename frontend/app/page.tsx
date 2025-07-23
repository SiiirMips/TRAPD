// frontend/nextjs_dashboard/app/page.tsx
import { supabase } from '../supabaseClient'; // Importiere den Supabase Client
import { format } from 'date-fns'; // Für bessere Datumsformatierung

// Definiere ein Interface für die Struktur der Log-Einträge
interface AttackerLog {
  id: string;
  timestamp: string;
  source_ip: string;
  honeypot_type: string;
  interaction_data: any; // JSONB-Feld
  status: string;
}

// Dies ist eine Server Component in Next.js App Router.
// Datenabruf kann direkt hier erfolgen.
export default async function HomePage() {
  let logs: AttackerLog[] = [];
  let error: string | null = null;

  try {
    // Daten aus der 'attacker_logs' Tabelle abrufen
    // Sortiere nach Zeitstempel absteigend (neueste zuerst)
    // Begrenze auf die letzten 50 Einträge für die Übersicht
    const { data, error: fetchError } = await supabase
      .from('attacker_logs')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(50);

    if (fetchError) {
      error = fetchError.message;
      console.error('Fehler beim Abrufen der Logs:', fetchError);
    } else {
      logs = data || [];
    }
  } catch (e: any) {
    error = e.message;
    console.error('Unerwarteter Fehler beim Supabase-Abruf:', e);
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-100 p-4 sm:p-6 lg:p-8">
      <div className="max-w-7xl mx-auto bg-white shadow-xl rounded-2xl overflow-hidden p-6 lg:p-10">
        <h1 className="text-4xl sm:text-5xl font-extrabold text-center text-gray-800 mb-8 tracking-tight">
          Honeypot Dashboard
        </h1>
        <p className="text-center text-gray-600 text-lg mb-10 max-w-2xl mx-auto">
          Übersicht der erfassten Angreiferinteraktionen und Honeypot-Aktivitäten.
        </p>

        {error && (
          <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 rounded-lg mb-6" role="alert">
            <p className="font-bold">Fehler beim Laden der Daten:</p>
            <p>{error}</p>
          </div>
        )}

        {logs.length === 0 && !error && (
          <div className="bg-blue-50 border-l-4 border-blue-500 text-blue-700 p-4 rounded-lg mb-6">
            <p className="font-bold">Keine Logs gefunden</p>
            <p>Noch keine Angreifer-Logs vorhanden. Starten Sie Ihre Honeypots, um Daten zu erfassen!</p>
          </div>
        )}

        {logs.length > 0 && (
          <div className="shadow-lg rounded-xl overflow-hidden border border-gray-200">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-100">
                  <tr>
                    <th className="px-4 py-3 sm:px-6 sm:py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                      Timestamp
                    </th>
                    <th className="px-4 py-3 sm:px-6 sm:py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                      IP-Adresse
                    </th>
                    <th className="px-4 py-3 sm:px-6 sm:py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                      Honeypot Typ
                    </th>
                    <th className="px-4 py-3 sm:px-6 sm:py-4 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                      Interaktions-Details
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-100">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-gray-50 transition-colors duration-150 ease-in-out">
                      <td className="px-4 py-3 sm:px-6 sm:py-4 whitespace-nowrap text-sm text-gray-800">
                        {format(new Date(log.timestamp), 'dd.MM.yyyy HH:mm:ss')}
                      </td>
                      <td className="px-4 py-3 sm:px-6 sm:py-4 whitespace-nowrap text-sm text-gray-800">
                        {log.source_ip}
                      </td>
                      <td className="px-4 py-3 sm:px-6 sm:py-4 whitespace-nowrap text-sm text-gray-800">
                        <span className={`px-2.5 py-0.5 inline-flex text-xs leading-5 font-semibold rounded-full ${
                          log.honeypot_type === 'http' ? 'bg-indigo-100 text-indigo-800' :
                          log.honeypot_type === 'ssh' ? 'bg-teal-100 text-teal-800' :
                          'bg-gray-200 text-gray-800'
                        }`}>
                          {log.honeypot_type.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 sm:px-6 sm:py-4 text-sm text-gray-600 max-w-sm truncate">
                        {/* Zeigt die wichtigsten Details an */}
                        {log.interaction_data?.request_path && (
                          <p className="mb-1">Pfad: <span className="font-medium text-gray-800">{log.interaction_data.request_path}</span></p>
                        )}
                        {log.interaction_data?.username_attempt && (
                          <p className="mb-1">Login: <span className="font-medium text-gray-800">{log.interaction_data.username_attempt}</span></p>
                        )}
                        {log.interaction_data?.command_executed && (
                          <p className="mb-1">Befehl: <span className="font-medium text-gray-800">{log.interaction_data.command_executed}</span></p>
                        )}
                        {log.interaction_data?.method && !log.interaction_data?.request_path && (
                          <p className="mb-1">Methode: <span className="font-medium text-gray-800">{log.interaction_data.method}</span></p>
                        )}
                        {/* Fallback für andere JSONB-Daten, wenn keine spezifischen Felder gefunden wurden */}
                        {!log.interaction_data?.request_path &&
                         !log.interaction_data?.username_attempt &&
                         !log.interaction_data?.command_executed &&
                         !log.interaction_data?.method &&
                         JSON.stringify(log.interaction_data).length > 2 ? (
                          <p className="text-xs text-gray-500 italic">
                            {JSON.stringify(log.interaction_data).substring(0, 70)}...
                          </p>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
