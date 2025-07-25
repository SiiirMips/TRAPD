"use client"

import { useState, useEffect, useMemo } from "react"
import { supabase } from "@/supabaseClient"
import { useTheme } from "@/components/theme-provider"
import { AppSidebar } from "@/components/app-sidebar"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Skeleton } from "@/components/ui/skeleton"
import { Button } from "@/components/ui/button"
import { ShieldAlert, Users, Activity, Globe, TrendingUp, Clock, Sun, Moon, Monitor } from "lucide-react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts"

// TypeScript-Interface für deine Log-Daten
interface AttackerLog {
  id: string;
  timestamp: string; // oder 'created_at' etc., an deinen Tabellennamen anpassen
  source_ip: string;
  honeypot_type: string;
}

export default function Page() {
  const [logs, setLogs] = useState<AttackerLog[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { theme, setTheme } = useTheme()

  useEffect(() => {
    const fetchDashboardData = async () => {
      setLoading(true)
      setError(null)
      try {
        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()

        const { data, error } = await supabase
          .from('attacker_logs')
          .select('id, timestamp, source_ip, honeypot_type')
          .gte('timestamp', twentyFourHoursAgo) // Nur Logs der letzten 24h
          .order('timestamp', { ascending: false })

        if (error) {
          throw error
        }
        
        setLogs(data || [])
      } catch (err: any) {
        console.error("Fehler beim Laden der Dashboard-Daten:", err)
        setError("Daten konnten nicht geladen werden.")
      } finally {
        setLoading(false)
      }
    }

    fetchDashboardData()
  }, [])
  
  // Alle Berechnungen für die Widgets werden hier gemacht.
  // useMemo sorgt dafür, dass sie nur neu laufen, wenn sich die 'logs' ändern.
  const dashboardData = useMemo(() => {
    if (!logs || logs.length === 0) {
      return {
        kpi: { totalAttacks: 0, uniqueAttackers: 0, topAttackType: "N/A", topCountry: "N/A" },
        hourlyAttacks: [],
        recentActivities: [],
        topAttackers: [],
        attackTypes: [],
      }
    }

    // 1. KPI-Daten berechnen
    const uniqueAttackers = new Set(logs.map(log => log.source_ip)).size
    
    const typeCounts = logs.reduce((acc, log) => {
      acc[log.honeypot_type] = (acc[log.honeypot_type] || 0) + 1
      return acc
    }, {} as Record<string, number>)
    
    const topAttackType = Object.keys(typeCounts).length > 0
      ? Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0][0]
      : "N/A"

    // 2. Angriffe pro Stunde
    const hourlyAttacks = Array(24).fill(0).map((_, i) => ({
      hour: `${String(i).padStart(2, '0')}:00`,
      attacks: 0
    }))
    logs.forEach(log => {
      const hour = new Date(log.timestamp).getHours()
      hourlyAttacks[hour].attacks++
    })
    
    // 3. Neueste Aktivitäten
    const recentActivities = logs.slice(0, 7).map(log => ({
      ...log,
      time: new Date(log.timestamp).toLocaleTimeString('de-DE'),
      country: "N/A", // Platzhalter für zukünftige Geo-IP-Analyse
      flag: "🏳️"
    }))

    // 4. Top 5 Angreifer
    const ipCounts = logs.reduce((acc, log) => {
      acc[log.source_ip] = (acc[log.source_ip] || 0) + 1
      return acc
    }, {} as Record<string, number>)

    const topAttackers = Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, attacks]) => ({ ip, attacks, country: "N/A" }))

    // 5. Angriffsverteilung (Kuchendiagramm)
    const totalAttacks = logs.length
    const attackTypeDistribution = Object.entries(typeCounts).map(([name, value]) => ({
      name: name.toUpperCase(),
      value: parseFloat(((value / totalAttacks) * 100).toFixed(1)),
    }))
    
    const COLORS: Record<string, string> = { SSH: "#ef4444", HTTP: "#f97316", FTP: "#eab308", TELNET: "#22c55e", DEFAULT: "#8b5cf6" }
    const attackTypesForPie = attackTypeDistribution.map(d => ({...d, color: COLORS[d.name] || COLORS.DEFAULT}));

    return {
      kpi: { totalAttacks, uniqueAttackers, topAttackType, topCountry: "N/A" },
      hourlyAttacks,
      recentActivities,
      topAttackers,
      attackTypes: attackTypesForPie
    }
  }, [logs])

  const getThemeIcon = () => {
    switch (theme) {
      case 'light': return <Sun className="h-4 w-4" />
      case 'dark': return <Moon className="h-4 w-4" />
      default: return <Monitor className="h-4 w-4" />
    }
  }

  const cycleTheme = () => {
    const themes: Array<'light' | 'dark' | 'system'> = ['light', 'dark', 'system']
    const currentIndex = themes.indexOf(theme as any)
    const nextIndex = (currentIndex + 1) % themes.length
    setTheme(themes[nextIndex])
  }

return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-12 border-b border-border bg-background/50 backdrop-blur-sm">
          <div className="flex items-center justify-between w-full px-4">
            <div className="flex items-center">
              <SidebarTrigger className="-ml-1" />
              <Separator
                orientation="vertical"
                className="mr-2 h-4"
              />
              <Breadcrumb>
                <BreadcrumbList>
                  <BreadcrumbItem className="hidden md:block">
                    <BreadcrumbLink href="/" className="text-muted-foreground hover:text-foreground transition-colors">
                      Dashboard
                    </BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator className="hidden md:block" />
                  <BreadcrumbItem>
                    <BreadcrumbPage className="text-foreground">Übersicht</BreadcrumbPage>
                  </BreadcrumbItem>
                </BreadcrumbList>
              </Breadcrumb>
            </div>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={cycleTheme}
              className="h-8 w-8 p-0 hover:bg-accent transition-colors"
              title={`Aktuell: ${theme === 'system' ? 'System' : theme === 'dark' ? 'Dunkel' : 'Hell'}`}
            >
              {getThemeIcon()}
            </Button>
          </div>
        </header>
        
        <main className="flex-1 space-y-6 p-6 bg-background text-foreground">
          {error && (
            <Card className="border-destructive/50 bg-destructive/10 dark:bg-destructive/5">
              <CardContent className="p-4">
                <div className="text-destructive">{error}</div>
              </CardContent>
            </Card>
          )}
          
          {/* KPI Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card className="border-border bg-card/50 backdrop-blur-sm hover:bg-card/80 transition-colors">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-card-foreground">Gesamte Angriffe</CardTitle>
                <ShieldAlert className="h-4 w-4 text-destructive" />
              </CardHeader>
              <CardContent>
                {loading ? <Skeleton className="h-8 w-1/2 bg-muted/50" /> : <div className="text-2xl font-bold text-foreground">{dashboardData.kpi.totalAttacks.toLocaleString()}</div>}
                <p className="text-xs text-muted-foreground">Letzte 24 Stunden</p>
              </CardContent>
            </Card>
            
            <Card className="border-border bg-card/50 backdrop-blur-sm hover:bg-card/80 transition-colors">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-card-foreground">Eindeutige Angreifer</CardTitle>
                <Users className="h-4 w-4 text-primary" />
              </CardHeader>
              <CardContent>
                {loading ? <Skeleton className="h-8 w-1/2 bg-muted/50" /> : <div className="text-2xl font-bold text-foreground">{dashboardData.kpi.uniqueAttackers}</div>}
                <p className="text-xs text-muted-foreground">Verschiedene IP-Adressen</p>
              </CardContent>
            </Card>
            
            <Card className="border-border bg-card/50 backdrop-blur-sm hover:bg-card/80 transition-colors">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-card-foreground">Häufigster Typ</CardTitle>
                <Activity className="h-4 w-4 text-amber-500" />
              </CardHeader>
              <CardContent>
                {loading ? <Skeleton className="h-8 w-1/2 bg-muted/50" /> : <div className="text-2xl font-bold text-foreground">{dashboardData.kpi.topAttackType.toUpperCase()}</div>}
                <p className="text-xs text-muted-foreground">Primärer Angriffsvektor</p>
              </CardContent>
            </Card>
            
            <Card className="border-border bg-card/50 backdrop-blur-sm hover:bg-card/80 transition-colors">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium text-card-foreground">Top-Angriffsziel</CardTitle>
                <Globe className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                {loading ? <Skeleton className="h-8 w-1/2 bg-muted/50" /> : <div className="text-2xl font-bold text-foreground">{dashboardData.kpi.topCountry}</div>}
                <p className="text-xs text-muted-foreground">Häufigstes Herkunftsland</p>
              </CardContent>
            </Card>
          </div>

          {/* Main Visualizations */}
          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="lg:col-span-1 border-border bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-card-foreground">
                  <TrendingUp className="h-5 w-5 text-primary" />
                  Angriffsaktivität der letzten 24h
                </CardTitle>
                <CardDescription className="text-muted-foreground">Angriffe pro Stunde zur Identifikation von Aktivitätsspitzen</CardDescription>
              </CardHeader>
              <CardContent>
                {loading ? <Skeleton className="h-[300px] w-full bg-muted/50" /> : (
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={dashboardData.hourlyAttacks}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                      <XAxis 
                        dataKey="hour" 
                        fontSize={12} 
                        tickLine={false} 
                        axisLine={false}
                        className="fill-muted-foreground"
                      />
                      <YAxis 
                        fontSize={12} 
                        tickLine={false} 
                        axisLine={false}
                        className="fill-muted-foreground"
                      />
                      <Tooltip 
                        contentStyle={{
                          backgroundColor: 'hsl(var(--popover))',
                          border: '1px solid hsl(var(--border))',
                          borderRadius: '6px',
                          color: 'hsl(var(--popover-foreground))'
                        }}
                      />
                      <Bar 
                        dataKey="attacks" 
                        fill="hsl(var(--destructive))" 
                        radius={[2, 2, 0, 0]}
                        className="fill-destructive"
                      />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>

            <Card className="border-border bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-card-foreground">
                  <Clock className="h-5 w-5 text-primary" />
                  Neueste Aktivitäten
                </CardTitle>
                <CardDescription className="text-muted-foreground">Live-Übersicht der aktuellsten Angriffe</CardDescription>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="space-y-4">
                    {Array(5).fill(0).map((_, i) => <Skeleton key={i} className="h-8 w-full bg-muted/50" />)}
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-muted/30">
                        <TableHead className="text-muted-foreground">Zeit</TableHead>
                        <TableHead className="text-muted-foreground">IP-Adresse</TableHead>
                        <TableHead className="text-muted-foreground">Typ</TableHead>
                        <TableHead className="text-muted-foreground">Land</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {dashboardData.recentActivities.map((activity) => (
                        <TableRow key={activity.id} className="border-border hover:bg-muted/20 transition-colors">
                          <TableCell className="font-mono text-sm text-foreground">{activity.time}</TableCell>
                          <TableCell className="font-mono text-foreground">{activity.source_ip}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="border-border text-foreground">
                              {activity.honeypot_type.toUpperCase()}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className="flex items-center gap-2 text-foreground">
                              <span>{activity.flag}</span>
                              <span>{activity.country}</span>
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Secondary Widgets */}
          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="border-border bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-card-foreground">Top 5 Angreifer</CardTitle>
                <CardDescription className="text-muted-foreground">IP-Adressen mit den meisten Angriffsversuchen</CardDescription>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="space-y-4">
                    {Array(5).fill(0).map((_, i) => <Skeleton key={i} className="h-8 w-full bg-muted/50" />)}
                  </div>
                ) : (
                  <div className="space-y-4">
                    {dashboardData.topAttackers.map((attacker, index) => (
                      <div key={index} className="flex items-center justify-between p-2 rounded-lg hover:bg-muted/20 transition-colors">
                        <div className="flex flex-col">
                          <span className="font-mono text-sm font-medium text-foreground">{attacker.ip}</span>
                          <span className="text-xs text-muted-foreground">{attacker.country}</span>
                        </div>
                        <Badge variant="destructive" className="bg-destructive/20 text-destructive border-destructive/30">
                          {attacker.attacks} Angriffe
                        </Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="border-border bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="text-card-foreground">Angriffsverteilung</CardTitle>
                <CardDescription className="text-muted-foreground">Prozentuale Verteilung der Honeypot-Typen</CardDescription>
              </CardHeader>
              <CardContent>
                {loading ? <Skeleton className="h-[200px] w-full bg-muted/50" /> : (
                  <>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie 
                          data={dashboardData.attackTypes} 
                          cx="50%" 
                          cy="50%" 
                          innerRadius={60} 
                          outerRadius={80} 
                          paddingAngle={5} 
                          dataKey="value"
                        >
                          {dashboardData.attackTypes.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip 
                          formatter={(value) => [`${value}%`, 'Anteil']}
                          contentStyle={{
                            backgroundColor: 'hsl(var(--popover))',
                            border: '1px solid hsl(var(--border))',
                            borderRadius: '6px',
                            color: 'hsl(var(--popover-foreground))'
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="grid grid-cols-2 gap-2 mt-4">
                      {dashboardData.attackTypes.map((type, index) => (
                        <div key={index} className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: type.color }} />
                          <span className="text-sm text-foreground">{type.name} ({type.value}%)</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}