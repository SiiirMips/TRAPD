"use client"

import { useEffect, useMemo, useState } from "react"
import { supabase } from "@/supabaseClient"
import { AppSidebar } from "@/components/app-sidebar"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Separator } from "@/components/ui/separator"
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Activity,
  Shield,
  AlertTriangle,
  Users,
  Scan,
  Eye,
  Globe,
  Clock,
  TrendingUp,
  Bot,
  Monitor,
  Fingerprint,
  Loader2,
} from "lucide-react"

type ThreatLevelKey = "critical" | "high" | "medium" | "low"

type ThreatLevels = Record<ThreatLevelKey, number>

interface DashboardStats {
  totalAttacks: number
  uniqueIPs: number
  threatsBlocked: number
  scannersDetected: number
  realTimeThreat: string | null
  topScanners: Array<{ name: string; count: number; confidence: number }>
  threatLevels: ThreatLevels
  browserFingerprints: number
  countries: Array<{ name: string; count: number; flag: string }>
  countryCount: number
}

interface ScannerStatisticsRow {
  scanner_type: string | null
  threat_level: string | null
  detection_count: number | null
  avg_confidence: number | null
}

interface ThreatOverviewRow {
  threat_level: string | null
  total_threats: number | null
}

interface CountryOverviewRow {
  country_code: string | null
  country_name: string | null
  attack_count: number | null
}

const THREAT_LEVEL_ORDER: ReadonlyArray<string> = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

const LEVEL_KEY_MAP: Record<string, ThreatLevelKey> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
}

const EMPTY_STATS: DashboardStats = {
  totalAttacks: 0,
  uniqueIPs: 0,
  threatsBlocked: 0,
  scannersDetected: 0,
  realTimeThreat: null,
  topScanners: [],
  threatLevels: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  },
  browserFingerprints: 0,
  countries: [],
  countryCount: 0,
}

const countryCodeToFlag = (code: string | null | undefined) => {
  if (!code || code.length !== 2) {
    return "🏳️"
  }

  const base = 127397 // regional indicator symbol letter A
  const characters = code
    .toUpperCase()
    .split("")
    .map((char) => base + char.charCodeAt(0))

  return String.fromCodePoint(...characters)
}

const normalizeThreatLevel = (value: string | null | undefined) =>
  value ? value.toUpperCase() : null

const getThreatColor = (level: string | null | undefined) => {
  switch (normalizeThreatLevel(level)) {
    case "CRITICAL":
      return "bg-red-500"
    case "HIGH":
      return "bg-orange-500"
    case "MEDIUM":
      return "bg-yellow-500"
    case "LOW":
      return "bg-green-500"
    default:
      return "bg-gray-500"
  }
}

async function loadDashboardStats(): Promise<DashboardStats> {
  const [
    totalAttacksResult,
    uniqueIpsResult,
    scannerStatsResult,
    threatOverviewResult,
    countriesResult,
    browserFingerprintsResult,
    latestThreatResult,
    countryCountResult,
  ] = await Promise.all([
    supabase
      .from("attacker_logs")
      .select<{ total: number }>("total:count()")
      .maybeSingle(),
    supabase
      .from("attacker_logs")
      .select<{ unique_ips: number }>("unique_ips:count(distinct source_ip)")
      .maybeSingle(),
    supabase
      .from("v_scanner_statistics")
      .select<ScannerStatisticsRow>(
        "scanner_type, threat_level, detection_count, avg_confidence"
      ),
    supabase
      .from("v_threat_overview")
      .select<ThreatOverviewRow>("threat_level, total_threats"),
    supabase
      .from("v_attacks_by_country")
      .select<CountryOverviewRow>("country_code, country_name, attack_count")
      .order("attack_count", { ascending: false })
      .limit(4),
    supabase
      .from("browser_fingerprints")
      .select<{ total: number }>("total:count()")
      .maybeSingle(),
    supabase
      .from("attacker_logs")
      .select<{ threat_level: string | null }>("threat_level")
      .not("threat_level", "is", "null")
      .order("timestamp", { ascending: false })
      .limit(1)
      .maybeSingle(),
    supabase
      .from("attacker_logs")
      .select<{ countries: number }>("countries:count(distinct country_code)")
      .not("country_code", "is", "null")
      .maybeSingle(),
  ])

  const errors = [
    totalAttacksResult.error,
    uniqueIpsResult.error,
    scannerStatsResult.error,
    threatOverviewResult.error,
    countriesResult.error,
    browserFingerprintsResult.error,
    latestThreatResult.error,
    countryCountResult.error,
  ].filter(Boolean)

  if (errors.length) {
    throw new Error(errors.map((err) => err?.message ?? "Unbekannter Fehler").join(" | "))
  }

  const threatLevels: ThreatLevels = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }

  threatOverviewResult.data?.forEach((row) => {
    const normalized = normalizeThreatLevel(row.threat_level ?? undefined)
    if (!normalized) return

    const key = LEVEL_KEY_MAP[normalized]
    if (key) {
      threatLevels[key] = row.total_threats ?? 0
    }
  })

  const scannerMap = new Map<
    string,
    { name: string; count: number; confidenceSum: number; sampleCount: number }
  >()

  scannerStatsResult.data?.forEach((row) => {
    const name = row.scanner_type ?? "Unbekannt"
    const detectionCount = row.detection_count ?? 0
    const avgConfidence = row.avg_confidence ?? 0

    if (!scannerMap.has(name)) {
      scannerMap.set(name, { name, count: 0, confidenceSum: 0, sampleCount: 0 })
    }

    const entry = scannerMap.get(name)!
    entry.count += detectionCount
    entry.confidenceSum += avgConfidence * detectionCount
    entry.sampleCount += detectionCount
  })

  const scannerEntries = Array.from(scannerMap.values())
  const topScanners = scannerEntries
    .map((entry) => {
      const confidence = entry.sampleCount > 0 ? entry.confidenceSum / entry.sampleCount : 0
      return {
        name: entry.name,
        count: entry.count,
        confidence: Math.max(0, Math.min(confidence, 1)),
      }
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 4)

  const countries = (countriesResult.data ?? []).map((row) => ({
    name: row.country_name ?? "Unbekannt",
    count: row.attack_count ?? 0,
    flag: countryCodeToFlag(row.country_code),
  }))

  const latestThreat = normalizeThreatLevel(latestThreatResult.data?.threat_level ?? undefined)
  const fallbackThreat = THREAT_LEVEL_ORDER.find((level) => {
    const key = LEVEL_KEY_MAP[level]
    return key ? threatLevels[key] > 0 : false
  })

  const threatsBlocked = threatLevels.critical + threatLevels.high

  return {
    totalAttacks: totalAttacksResult.data?.total ?? 0,
    uniqueIPs: uniqueIpsResult.data?.unique_ips ?? 0,
    threatsBlocked,
    scannersDetected: scannerEntries.length,
    realTimeThreat: latestThreat ?? fallbackThreat ?? null,
    topScanners,
    threatLevels,
    browserFingerprints: browserFingerprintsResult.data?.total ?? 0,
    countries,
    countryCount: countryCountResult.data?.countries ?? countries.length,
  }
}

export default function Page() {
  const [stats, setStats] = useState<DashboardStats>(EMPTY_STATS)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true

    const fetchStats = async () => {
      setLoading(true)
      setError(null)
      try {
        const data = await loadDashboardStats()
        if (active) {
          setStats(data)
        }
      } catch (err) {
        console.error("Fehler beim Laden der Dashboard-Daten", err)
        if (active) {
          setError("Dashboard-Daten konnten nicht geladen werden. Bitte versuche es später erneut.")
          setStats(EMPTY_STATS)
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    fetchStats()

    return () => {
      active = false
    }
  }, [])

  const threatBadgeLabel = stats.realTimeThreat ?? "UNKNOWN"
  const topScannerNames = useMemo(() => {
    if (!stats.topScanners.length) return "Keine Scanner erkannt"
    return stats.topScanners
      .slice(0, 3)
      .map((scanner) => scanner.name)
      .join(", ")
  }, [stats.topScanners])

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-12">
          <div className="flex items-center gap-2 px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator
              orientation="vertical"
              className="mr-2 data-[orientation=vertical]:h-4"
            />
            <Breadcrumb>
              <BreadcrumbList>
                <BreadcrumbItem className="hidden md:block">
                  <BreadcrumbLink href="/dashboard">
                    🍯 Honeypot Guardian
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem>
                  <BreadcrumbPage>Advanced Fingerprinting Dashboard</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </header>
        
        <div className="flex flex-1 flex-col gap-6 p-6 pt-0">
          {/* Real-time Status Bar */}
          <div className="flex items-center justify-between p-4 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg text-white">
            <div className="flex items-center gap-3">
              <Shield className="h-6 w-6" />
              <div>
                <h2 className="text-lg font-semibold">🔍 Advanced Fingerprinting System</h2>
                <p className="text-sm opacity-90">Real-time Scanner Detection & Browser Fingerprinting</p>
              </div>
            </div>
            <Badge className={`${getThreatColor(threatBadgeLabel)} text-white px-3 py-1 flex items-center gap-2`}>
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              THREAT LEVEL: {threatBadgeLabel}
            </Badge>
          </div>

          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
              {error}
            </div>
          )}

          {/* Key Metrics Grid */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card className="border-l-4 border-l-blue-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Attacks</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-8 w-24" />
                ) : (
                  <div className="text-2xl font-bold">{stats.totalAttacks.toLocaleString()}</div>
                )}
                <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                  <TrendingUp className="h-3 w-3" />
                  {loading
                    ? "Berechnung läuft..."
                    : `${stats.threatsBlocked} High/Critical threats blocked`}
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-green-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Unique IPs</CardTitle>
                <Users className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-8 w-16" />
                ) : (
                  <div className="text-2xl font-bold">{stats.uniqueIPs}</div>
                )}
                <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                  <Globe className="h-3 w-3" />
                  {loading
                    ? "Ermittle Regionen..."
                    : stats.countryCount > 0
                      ? `From ${stats.countryCount} countries`
                      : "Keine Geodaten"}
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-orange-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Scanners Detected</CardTitle>
                <Scan className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-8 w-16" />
                ) : (
                  <div className="text-2xl font-bold">{stats.scannersDetected}</div>
                )}
                <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                  <Bot className="h-3 w-3" />
                  {loading ? "Scanner werden geladen..." : topScannerNames}
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-purple-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Browser Fingerprints</CardTitle>
                <Fingerprint className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-8 w-20" />
                ) : (
                  <div className="text-2xl font-bold">{stats.browserFingerprints}</div>
                )}
                <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                  <Monitor className="h-3 w-3" />
                  {loading ? "Synchronisiere Fingerprints..." : "Canvas, WebGL, Audio"}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Analytics Grid */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            
            {/* Scanner Detection Card */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Scan className="h-5 w-5" />
                  🔍 Scanner Detection Results
                </CardTitle>
                <CardDescription>
                  Real-time detection of scanning tools with confidence scores
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {loading ? (
                  Array.from({ length: 4 }).map((_, index) => (
                    <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                      <div className="flex items-center gap-3">
                        <Skeleton className="h-6 w-12" />
                        <div className="space-y-1">
                          <Skeleton className="h-4 w-32" />
                          <Skeleton className="h-3 w-20" />
                        </div>
                      </div>
                      <Skeleton className="h-3 w-24" />
                    </div>
                  ))
                ) : stats.topScanners.length ? (
                  stats.topScanners.map((scanner, index) => (
                    <div key={scanner.name} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline">#{index + 1}</Badge>
                        <div>
                          <p className="font-medium">{scanner.name}</p>
                          <p className="text-sm text-muted-foreground">{scanner.count} detections</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-medium">{(scanner.confidence * 100).toFixed(1)}%</p>
                        <Progress value={scanner.confidence * 100} className="w-20" />
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-muted-foreground">Keine Scanner-Daten verfügbar.</p>
                )}
              </CardContent>
            </Card>

            {/* Threat Level Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5" />
                  🚨 Threat Levels
                </CardTitle>
                <CardDescription>
                  Distribution of threat assessments
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {[
                  { label: "Critical", color: "bg-red-500", value: stats.threatLevels.critical, badge: "destructive" as const },
                  { label: "High", color: "bg-orange-500", value: stats.threatLevels.high, badge: "secondary" as const },
                  { label: "Medium", color: "bg-yellow-500", value: stats.threatLevels.medium, badge: "outline" as const },
                  { label: "Low", color: "bg-green-500", value: stats.threatLevels.low, badge: "outline" as const },
                ].map((item) => (
                  <div key={item.label} className="flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <div className={`w-3 h-3 rounded-full ${item.color}`}></div>
                      {item.label}
                    </span>
                    {loading ? (
                      <Skeleton className="h-6 w-10" />
                    ) : (
                      <Badge variant={item.badge}>{item.value}</Badge>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Geographic Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  🌍 Attack Origins
                </CardTitle>
                <CardDescription>
                  Top attacking countries
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {loading ? (
                  Array.from({ length: 4 }).map((_, index) => (
                    <div key={index} className="flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <Skeleton className="h-6 w-6" />
                        <Skeleton className="h-4 w-24" />
                      </span>
                      <Skeleton className="h-6 w-12" />
                    </div>
                  ))
                ) : stats.countries.length ? (
                  stats.countries.map((country) => (
                    <div key={`${country.name}-${country.flag}`} className="flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <span className="text-lg">{country.flag}</span>
                        {country.name}
                      </span>
                      <Badge variant="outline">{country.count}</Badge>
                    </div>
                  ))
                ) : (
                  <p className="text-sm text-muted-foreground">Keine Geo-Daten verfügbar.</p>
                )}
              </CardContent>
            </Card>

            {/* Browser Fingerprinting Stats */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5" />
                  🔍 Browser Fingerprinting
                </CardTitle>
                <CardDescription>
                  JavaScript fingerprinting results
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Canvas Fingerprints</span>
                    <span>142</span>
                  </div>
                  <Progress value={85} />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>WebGL Fingerprints</span>
                    <span>134</span>
                  </div>
                  <Progress value={80} />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Audio Fingerprints</span>
                    <span>89</span>
                  </div>
                  <Progress value={65} />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Real Browsers</span>
                    <span>23</span>
                  </div>
                  <Progress value={15} />
                </div>
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  ⚡ Recent Activity
                </CardTitle>
                <CardDescription>
                  Latest fingerprinting detections
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="text-sm space-y-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="destructive" className="text-xs">NMAP</Badge>
                    <span className="text-muted-foreground">192.168.1.100</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-xs">MASS</Badge>
                    <span className="text-muted-foreground">10.0.0.55</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">GOBU</Badge>
                    <span className="text-muted-foreground">172.16.0.23</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className="text-xs">BRWS</Badge>
                    <span className="text-muted-foreground">203.0.113.45</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Real-time Monitoring Section */}
          <Card className="bg-gradient-to-r from-slate-900 to-slate-800 text-white">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5" />
                🎯 Real-time Fingerprinting Monitor
              </CardTitle>
              <CardDescription className="text-slate-300">
                Live feed of advanced fingerprinting detections
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 font-mono text-sm">
                <div className="flex items-center gap-3 p-2 rounded bg-black/20">
                  <Badge className="bg-red-500">CRIT</Badge>
                  <span className="text-green-400">13:42:15</span>
                  <span>Nmap NSE Script detected → 192.168.1.100 (RU)</span>
                  <Badge variant="outline" className="ml-auto">95% confidence</Badge>
                </div>
                <div className="flex items-center gap-3 p-2 rounded bg-black/20">
                  <Badge className="bg-orange-500">HIGH</Badge>
                  <span className="text-green-400">13:41:58</span>
                  <span>Masscan burst detected → 10.0.0.55 (CN)</span>
                  <Badge variant="outline" className="ml-auto">92% confidence</Badge>
                </div>
                <div className="flex items-center gap-3 p-2 rounded bg-black/20">
                  <Badge className="bg-blue-500">INFO</Badge>
                  <span className="text-green-400">13:41:42</span>
                  <span>Browser fingerprint collected → 203.0.113.45 (US)</span>
                  <Badge variant="outline" className="ml-auto">Canvas+WebGL</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
