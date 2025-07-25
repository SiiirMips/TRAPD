"use client";

import { useState, useEffect, useMemo } from 'react';
import { supabase } from '../supabaseClient';
import { format } from 'date-fns';
import { Search, Filter, RefreshCw, Activity, Shield, AlertTriangle, Sun, Moon } from 'lucide-react';
import { useTheme } from '@/components/theme-provider';

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
  const { theme, setTheme } = useTheme();

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
      case 'http': return 'bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-500/30 hover:bg-blue-500/30 dark:hover:bg-blue-500/20';
      case 'ssh': return 'bg-green-500/20 text-green-700 dark:text-green-300 border-green-500/30 hover:bg-green-500/30 dark:hover:bg-green-500/20';
      case 'ftp': return 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30 hover:bg-amber-500/30 dark:hover:bg-amber-500/20';
      case 'telnet': return 'bg-red-500/20 text-red-700 dark:text-red-300 border-red-500/30 hover:bg-red-500/30 dark:hover:bg-red-500/20';
      default: return 'bg-purple-500/20 text-purple-700 dark:text-purple-300 border-purple-500/30 hover:bg-purple-500/30 dark:hover:bg-purple-500/20';
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground transition-colors duration-300 p-4 sm:p-6 lg:p-8">
      <div className="container mx-auto max-w-7xl">
        {/* Header with Theme Toggle */}
        <div className="text-center mb-8">
          <div className="flex justify-end mb-4">
            <button
              onClick={() => setTheme(theme === 'dark' ? 'light' : theme === 'light' ? 'system' : 'dark')}
              className="p-2 rounded-lg bg-card hover:bg-accent border border-border transition-colors"
              title={`Aktuell: ${theme === 'system' ? 'System' : theme === 'dark' ? 'Dunkel' : 'Hell'}`}
            >
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : 
               theme === 'light' ? <Moon className="h-4 w-4" /> : 
               <Activity className="h-4 w-4" />}
            </button>
          </div>
          
          <h1 className="text-4xl sm:text-5xl font-bold mb-4">
            <span className="bg-gradient-to-r from-amber-800 via-amber-700 to-amber-600 dark:from-amber-400 dark:via-amber-300 dark:to-amber-200 text-transparent bg-clip-text">
              Project Guardian
            </span>
          </h1>
          <p className="text-lg text-muted-foreground mb-2">Honeypot Monitoring Dashboard</p>
          <p className="text-sm text-muted-foreground">
            Letzte Aktualisierung: {format(lastUpdate, 'dd.MM.yyyy HH:mm:ss')}
          </p>
        </div>

        {/* Stats Cards with improved dark mode */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card className="border border-border bg-gradient-to-r from-amber-500/90 to-amber-600/90 dark:from-amber-600/80 dark:to-amber-700/80 text-white shadow-lg backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white/90">Gesamte Angriffe</CardTitle>
              <AlertTriangle className="h-4 w-4 text-white/80" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.totalAttacks}</div>
            </CardContent>
          </Card>
          
          <Card className="border border-border bg-gradient-to-r from-orange-500/90 to-orange-600/90 dark:from-orange-600/80 dark:to-orange-700/80 text-white shadow-lg backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white/90">Eindeutige IPs</CardTitle>
              <Activity className="h-4 w-4 text-white/80" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{stats.uniqueIPs}</div>
            </CardContent>
          </Card>
          
          <Card className="border border-border bg-gradient-to-r from-amber-600/90 to-amber-700/90 dark:from-amber-700/80 dark:to-amber-800/80 text-white shadow-lg backdrop-blur-sm">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-white/90">Aktive Honeypots</CardTitle>
              <Shield className="h-4 w-4 text-white/80" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">{Object.keys(stats.honeypotTypes).length}</div>
            </CardContent>
          </Card>
        </div>

        {/* Controls with better dark mode styling */}
        <Card className="mb-6 border border-border bg-card/50 backdrop-blur-sm shadow-lg">
          <CardHeader>
            <CardTitle className="text-xl">Filter & Suche</CardTitle>
            <CardDescription>Durchsuchen und filtern Sie die Angreifer-Logs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                <Input
                  placeholder="Suche nach IP, Typ oder Details..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 bg-background/50 border-border"
                />
              </div>
              
              <Select value={filterType} onValueChange={setFilterType}>
                <SelectTrigger className="w-full sm:w-48 bg-background/50 border-border">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-popover border-border backdrop-blur-sm">
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
                className="bg-primary hover:bg-primary/90 text-primary-foreground"
              >
                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                Aktualisieren
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Error Display with dark mode */}
        {error && (
          <Card className="mb-6 border-destructive/50 bg-destructive/10 dark:bg-destructive/5">
            <CardContent className="pt-6">
              <div className="flex items-center text-destructive">
                <AlertTriangle className="h-5 w-5 mr-2" />
                <span className="font-semibold">Fehler:</span>
                <span className="ml-2">{error}</span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Logs Table with enhanced dark mode */}
        <Card className="border border-border bg-card/50 backdrop-blur-sm shadow-xl">
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
                    <Skeleton className="h-12 w-12 bg-muted/50" />
                    <div className="space-y-2 flex-1">
                      <Skeleton className="h-4 w-full bg-muted/50" />
                      <Skeleton className="h-4 w-3/4 bg-muted/50" />
                    </div>
                  </div>
                ))}
              </div>
            ) : filteredLogs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
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
                    <TableRow className="bg-muted/30 dark:bg-muted/20 border-border">
                      <TableHead className="font-semibold text-foreground">Timestamp</TableHead>
                      <TableHead className="font-semibold text-foreground">IP-Adresse</TableHead>
                      <TableHead className="font-semibold text-foreground">Honeypot-Typ</TableHead>
                      <TableHead className="font-semibold text-foreground">Interaktions-Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredLogs.map((log) => (
                      <TableRow key={log.id} className="hover:bg-muted/20 dark:hover:bg-muted/10 transition-colors border-border">
                        <TableCell className="font-medium">
                          {format(new Date(log.timestamp), 'dd.MM.yyyy HH:mm:ss')}
                        </TableCell>
                        <TableCell>
                          <code className="bg-muted/50 dark:bg-muted/30 px-2 py-1 rounded text-sm border border-border">
                            {log.source_ip}
                          </code>
                        </TableCell>
                        <TableCell>
                          <Badge className={getHoneypotBadgeColor(log.honeypot_type)} variant="outline">
                            {log.honeypot_type.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-md">
                          <div className="space-y-1 text-sm">
                            {log.interaction_data?.request_path && (
                              <div><span className="font-medium">Pfad:</span> <code className="bg-muted/50 dark:bg-muted/30 px-1 rounded border border-border">{log.interaction_data.request_path}</code></div>
                            )}
                            {log.interaction_data?.username_attempt && (
                              <div><span className="font-medium">User:</span> <code className="bg-muted/50 dark:bg-muted/30 px-1 rounded border border-border">{log.interaction_data.username_attempt}</code></div>
                            )}
                            {log.interaction_data?.command_executed && (
                              <div><span className="font-medium">Befehl:</span> <code className="bg-muted/50 dark:bg-muted/30 px-1 rounded border border-border">{log.interaction_data.command_executed}</code></div>
                            )}
                            {log.interaction_data?.method && (
                              <div><span className="font-medium">Methode:</span> <Badge variant="outline">{log.interaction_data.method}</Badge></div>
                            )}
                            {!Object.keys(log.interaction_data || {}).some(key => 
                              ['request_path', 'username_attempt', 'command_executed', 'method'].includes(key)
                            ) && Object.keys(log.interaction_data || {}).length > 0 && (
                              <div className="text-muted-foreground italic">
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