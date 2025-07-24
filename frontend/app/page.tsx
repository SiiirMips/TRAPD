"use client";

import { useState, useEffect, useMemo } from 'react';
import { supabase } from '../supabaseClient';
import { format } from 'date-fns';
import { Search, Filter, RefreshCw, Activity, Shield, AlertTriangle } from 'lucide-react';

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

interface AttackerLog {
  id: string;
  timestamp: string;
  source_ip: string;
  honeypot_type: string;
  interaction_data: any;
  status: string;
}

export default function HomePage() {
  const [logs, setLogs] = useState<AttackerLog[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const { data, error: fetchError } = await supabase
        .from('attacker_logs')
        .select('*')
        .order('timestamp', { ascending: false })
        .limit(100);

      if (fetchError) {
        setError(fetchError.message);
        console.error('Fehler beim Abrufen der Logs:', fetchError);
      } else {
        setLogs(data || []);
        setError(null);
        setLastUpdate(new Date());
      }
    } catch (e: any) {
      setError(e.message);
      console.error('Unerwarteter Fehler beim Supabase-Abruf:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();

    // Auto-refresh every 5 minutes
    const interval = setInterval(fetchLogs, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchesSearch = 
        log.source_ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.honeypot_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        JSON.stringify(log.interaction_data).toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesFilter = filterType === 'all' || log.honeypot_type === filterType;
      
      return matchesSearch && matchesFilter;
    });
  }, [logs, searchTerm, filterType]);

  const stats = useMemo(() => {
    const totalAttacks = logs.length;
    const uniqueIPs = new Set(logs.map(log => log.source_ip)).size;
    const honeypotTypes = logs.reduce((acc, log) => {
      acc[log.honeypot_type] = (acc[log.honeypot_type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    return { totalAttacks, uniqueIPs, honeypotTypes };
  }, [logs]);

  const getHoneypotBadgeColor = (type: string) => {
    switch (type) {
      case 'http': return 'bg-blue-100 text-blue-800 hover:bg-blue-200';
      case 'ssh': return 'bg-green-100 text-green-800 hover:bg-green-200';
      case 'ftp': return 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200';
      case 'telnet': return 'bg-red-100 text-red-800 hover:bg-red-200';
      default: return 'bg-purple-100 text-purple-800 hover:bg-purple-200';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-4 sm:p-6 lg:p-8">
      <div className="container mx-auto max-w-7xl">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl sm:text-5xl font-bold mb-4">
            <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-600 text-transparent bg-clip-text">
              Honeypot
            </span>
          </h1>
          <p className="text-lg text-slate-600 mb-2">Honeypot Monitoring Dashboard</p>
          <p className="text-sm text-slate-500">
            Letzte Aktualisierung: {format(lastUpdate, 'dd.MM.yyyy HH:mm:ss')}
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card className="border-0 shadow-lg bg-gradient-to-r from-blue-500 to-blue-600 text-white">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Gesamte Angriffe</CardTitle>
              <AlertTriangle className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.totalAttacks}</div>
            </CardContent>
          </Card>
          
          <Card className="border-0 shadow-lg bg-gradient-to-r from-green-500 to-green-600 text-white">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Eindeutige IPs</CardTitle>
              <Activity className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.uniqueIPs}</div>
            </CardContent>
          </Card>
          
          <Card className="border-0 shadow-lg bg-gradient-to-r from-purple-500 to-purple-600 text-white">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Aktive Honeypots</CardTitle>
              <Shield className="h-4 w-4" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{Object.keys(stats.honeypotTypes).length}</div>
            </CardContent>
          </Card>
        </div>

        {/* Controls */}
        <Card className="mb-6 border-0 shadow-lg">
          <CardHeader>
            <CardTitle className="text-xl">Filter & Suche</CardTitle>
            <CardDescription>Durchsuchen und filtern Sie die Angreifer-Logs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400 h-4 w-4" />
                <Input
                  placeholder="Suche nach IP, Typ oder Details..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
              
              <Select value={filterType} onValueChange={setFilterType}>
                <SelectTrigger className="w-full sm:w-48">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Alle Typen</SelectItem>
                  {Object.keys(stats.honeypotTypes).map(type => (
                    <SelectItem key={type} value={type} className="capitalize">
                      {type} ({stats.honeypotTypes[type]})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              
              <Button 
                onClick={fetchLogs} 
                disabled={loading}
                className="bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                Aktualisieren
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Error Display */}
        {error && (
          <Card className="mb-6 border-red-200 bg-red-50">
            <CardContent className="pt-6">
              <div className="flex items-center text-red-700">
                <AlertTriangle className="h-5 w-5 mr-2" />
                <span className="font-semibold">Fehler:</span>
                <span className="ml-2">{error}</span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Logs Table */}
        <Card className="border-0 shadow-xl">
          <CardHeader>
            <CardTitle className="text-xl">Angreifer-Logs</CardTitle>
            <CardDescription>
              {filteredLogs.length} von {logs.length} Einträgen
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="p-6 space-y-4">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="flex space-x-4">
                    <Skeleton className="h-12 w-12" />
                    <div className="space-y-2 flex-1">
                      <Skeleton className="h-4 w-full" />
                      <Skeleton className="h-4 w-3/4" />
                    </div>
                  </div>
                ))}
              </div>
            ) : filteredLogs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-slate-500">
                <Shield className="h-16 w-16 mb-4 opacity-50" />
                <p className="text-lg font-medium mb-2">
                  {logs.length === 0 ? 'Keine Logs verfügbar' : 'Keine Logs gefunden'}
                </p>
                <p className="text-sm">
                  {logs.length === 0 
                    ? 'Starten Sie Ihre Honeypots, um Aktivitäten zu sehen!' 
                    : 'Versuchen Sie, Ihre Suchkriterien anzupassen.'
                  }
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-slate-50">
                      <TableHead className="font-semibold text-slate-700">Timestamp</TableHead>
                      <TableHead className="font-semibold text-slate-700">IP-Adresse</TableHead>
                      <TableHead className="font-semibold text-slate-700">Honeypot-Typ</TableHead>
                      <TableHead className="font-semibold text-slate-700">Interaktions-Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredLogs.map((log) => (
                      <TableRow key={log.id} className="hover:bg-slate-50 transition-colors">
                        <TableCell className="font-medium">
                          {format(new Date(log.timestamp), 'dd.MM.yyyy HH:mm:ss')}
                        </TableCell>
                        <TableCell>
                          <code className="bg-slate-100 px-2 py-1 rounded text-sm">
                            {log.source_ip}
                          </code>
                        </TableCell>
                        <TableCell>
                          <Badge className={getHoneypotBadgeColor(log.honeypot_type)}>
                            {log.honeypot_type.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-md">
                          <div className="space-y-1 text-sm">
                            {log.interaction_data?.request_path && (
                              <div><span className="font-medium">Pfad:</span> <code className="bg-slate-100 px-1 rounded">{log.interaction_data.request_path}</code></div>
                            )}
                            {log.interaction_data?.username_attempt && (
                              <div><span className="font-medium">User:</span> <code className="bg-slate-100 px-1 rounded">{log.interaction_data.username_attempt}</code></div>
                            )}
                            {log.interaction_data?.command_executed && (
                              <div><span className="font-medium">Befehl:</span> <code className="bg-slate-100 px-1 rounded">{log.interaction_data.command_executed}</code></div>
                            )}
                            {log.interaction_data?.method && (
                              <div><span className="font-medium">Methode:</span> <Badge variant="outline">{log.interaction_data.method}</Badge></div>
                            )}
                            {!Object.keys(log.interaction_data || {}).some(key => 
                              ['request_path', 'username_attempt', 'command_executed', 'method'].includes(key)
                            ) && Object.keys(log.interaction_data || {}).length > 0 && (
                              <div className="text-slate-500 italic">
                                {JSON.stringify(log.interaction_data).substring(0, 100)}...
                              </div>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
