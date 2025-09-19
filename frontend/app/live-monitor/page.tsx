"use client"

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
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { DisinformationList } from "@/components/disinformation/disinformation-list"
import type { DisinformationEntry } from "@/components/disinformation/types"
import {
  Activity,
  Shield,
  AlertTriangle,
  Globe,
  Users,
  Server,
  RefreshCw,
  MapPin,
  Clock,
  Zap,
  Radar
} from "lucide-react"
import { useState, useEffect, useCallback, useRef } from "react"
import { supabase } from "@/supabaseClient"
import type { RealtimeChannel, RealtimePostgresInsertPayload } from "@supabase/supabase-js"

const ACTIVE_WINDOW_MINUTES = 15
const MAX_STORED_EVENTS = 200
const MAX_STORED_DISINFORMATION = 60
const LOG_MATCH_WINDOW_MS = 5 * 60 * 1000

const severityLabelMap = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low"
} as const

type Severity = keyof typeof severityLabelMap

type ThreatData = {
  activeThreats: number
  blockedAttempts: number
  honeypotStatus: "connecting" | "active" | "reconnecting"
  connectedAttackers: number
}

type AttackEvent = {
  id: string
  ip: string
  country: string
  countryKey: string
  type: string
  severity: Severity
  threatLevelLabel: string
  port: string
  userAgent: string
  payload: string
  timestamp: string
  scanner: string
  scanPattern: string
  toolConfidence: number | null
  isRealBrowser: boolean | null
}

type CountryStat = {
  country: string
  attacks: number
  percentage: number
}

type ProtocolStat = {
  type: string
  count: number
}

type ScannerStat = {
  label: string
  count: number
  percentage: number
}

type TimelineBucket = {
  iso: string
  label: string
  count: number
}

type SeveritySummary = Record<Severity, number>

type GenericRecord = Record<string, unknown>

function ensureRecord(value: unknown): GenericRecord | null {
  if (!value) return null
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as GenericRecord
    } catch {
      return null
    }
  }
  if (typeof value === "object") {
    return value as GenericRecord
  }
  return null
}

function getStringField(record: GenericRecord, key: string): string | undefined {
  const value = record[key]
  if (typeof value === "string" && value.trim()) {
    return value.trim()
  }
  if (typeof value === "number") {
    return value.toString()
  }
  return undefined
}

function deriveThreatLevel(record: GenericRecord): Severity {
  const rawLevel = record["threat_level"]
  const level = typeof rawLevel === "string" ? rawLevel.toLowerCase() : ""
  if (level === "critical") return "critical"
  if (level === "high") return "high"
  if (level === "medium") return "medium"
  if (level === "low") return "low"

  const confidenceValue = record["tool_confidence"]
  const confidence = typeof confidenceValue === "number"
    ? confidenceValue
    : typeof confidenceValue === "string"
      ? Number(confidenceValue)
      : undefined

  if (typeof confidence === "number" && !Number.isNaN(confidence)) {
    if (confidence >= 0.75) return "high"
    if (confidence >= 0.4) return "medium"
  }

  const hasScanner = typeof record["scanner_type"] === "string" && (record["scanner_type"] as string).trim() !== ""
  if (hasScanner) {
    return "medium"
  }

  return "low"
}

function buildCountryLabel(record: GenericRecord): { key: string; label: string } {
  const rawCode = getStringField(record, "country_code")
  const countryCode = rawCode ? rawCode.toUpperCase() : ""
  const countryName = getStringField(record, "country_name") ?? ""
  if (countryName && countryCode) {
    return { key: countryCode, label: `${countryName} (${countryCode})` }
  }
  if (countryName) {
    return { key: countryName, label: countryName }
  }
  if (countryCode) {
    return { key: countryCode, label: countryCode }
  }
  return { key: "Unknown", label: "Unknown" }
}

function extractUserAgent(data: GenericRecord | null): string {
  if (!data) return "Unknown"
  const userAgent = getStringField(data, "user_agent")
  if (userAgent) {
    return userAgent
  }
  const headers = ensureRecord(data["headers"])
  if (headers) {
    const headerUA = getStringField(headers, "User-Agent")
      ?? getStringField(headers, "user-agent")
      ?? getStringField(headers, "USER_AGENT")
    if (headerUA) {
      return headerUA
    }
  }
  const client = getStringField(data, "client")
  if (client) {
    return client
  }
  return "Unknown"
}

function extractPayload(data: GenericRecord | null): string {
  if (!data) return "—"
  const candidates = ["payload", "command", "request", "message", "body", "data"]
  for (const key of candidates) {
    const value = data[key]
    if (typeof value === "string" && value.trim()) {
      return value.trim()
    }
  }
  return "—"
}

function extractPort(record: GenericRecord, interaction: GenericRecord | null): string {
  const candidates = [
    record["target_port"],
    record["destination_port"],
    interaction?.["port"],
    interaction?.["dst_port"],
    interaction?.["destination_port"],
    interaction?.["local_port"],
    interaction?.["remote_port"]
  ]

  for (const candidate of candidates) {
    if (typeof candidate === "number" && Number.isFinite(candidate)) {
      return String(candidate)
    }
    if (typeof candidate === "string" && candidate.trim()) {
      const numeric = Number(candidate)
      return Number.isNaN(numeric) ? candidate.trim() : String(numeric)
    }
  }

  return "—"
}

function normalizeAttackRecord(raw: GenericRecord): AttackEvent | null {
  if (!raw) return null
  const id = getStringField(raw, "id")
    ?? getStringField(raw, "uuid")
    ?? getStringField(raw, "log_id")
  const timestampValue = getStringField(raw, "timestamp")
    ?? getStringField(raw, "inserted_at")
    ?? getStringField(raw, "created_at")
  if (!id || !timestampValue) return null

  const interaction = ensureRecord(raw["interaction_data"])
  const severity = deriveThreatLevel(raw)
  const { key: countryKey, label: countryLabel } = buildCountryLabel(raw)
  const scannerRaw = getStringField(raw, "scanner_type")
  const scannerLabel = !scannerRaw || scannerRaw.toLowerCase() === "unknown"
    ? "Unidentified"
    : scannerRaw
  const scannerForType = scannerRaw && scannerRaw.toLowerCase() !== "unknown"
    ? scannerRaw
    : undefined
  const typeParts = [getStringField(raw, "honeypot_type"), scannerForType]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .map(value => value.trim())

  const type = typeParts.length > 0 ? typeParts.join(" · ") : "Unknown activity"
  const rawThreatLevel = getStringField(raw, "threat_level")
  const threatLevelLabel = rawThreatLevel ?? severityLabelMap[severity]

  const scanPatternRaw = getStringField(raw, "scan_pattern")
  const scanPattern = scanPatternRaw && scanPatternRaw.trim()
    ? scanPatternRaw.trim()
    : "unknown"

  const confidenceValue = raw["tool_confidence"]
  let toolConfidence: number | null = null
  if (typeof confidenceValue === "number" && Number.isFinite(confidenceValue)) {
    toolConfidence = confidenceValue
  } else if (typeof confidenceValue === "string") {
    const parsed = Number(confidenceValue)
    toolConfidence = Number.isNaN(parsed) ? null : parsed
  }

  const rawBrowserFlag = raw["is_real_browser"]
  let isRealBrowser: boolean | null = null
  if (typeof rawBrowserFlag === "boolean") {
    isRealBrowser = rawBrowserFlag
  } else if (typeof rawBrowserFlag === "string") {
    const lowered = rawBrowserFlag.trim().toLowerCase()
    if (lowered === "true") {
      isRealBrowser = true
    } else if (lowered === "false") {
      isRealBrowser = false
    }
  }

  const timestamp = new Date(timestampValue).toISOString()

  return {
    id,
    ip: getStringField(raw, "source_ip")
      ?? getStringField(raw, "ip")
      ?? "Unknown",
    country: countryLabel,
    countryKey,
    type,
    severity,
    threatLevelLabel,
    port: extractPort(raw, interaction),
    userAgent: extractUserAgent(interaction),
    payload: extractPayload(interaction),
    timestamp,
    scanner: scannerLabel,
    scanPattern,
    toolConfidence,
    isRealBrowser
  }
}

function computeActiveThreats(attacks: AttackEvent[]): number {
  const threshold = Date.now() - ACTIVE_WINDOW_MINUTES * 60 * 1000
  return attacks.filter(attack => Date.parse(attack.timestamp) >= threshold).length
}

function buildTopCountryStats(attacks: AttackEvent[]): CountryStat[] {
  const counts = new Map<string, { label: string; count: number }>()
  for (const attack of attacks) {
    const entry = counts.get(attack.countryKey)
    if (entry) {
      entry.count += 1
    } else {
      counts.set(attack.countryKey, { label: attack.country, count: 1 })
    }
  }
  const totals = Array.from(counts.values())
  const totalAttacks = totals.reduce((sum, item) => sum + item.count, 0)
  return totals
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
    .map(item => ({
      country: item.label,
      attacks: item.count,
      percentage: totalAttacks > 0 ? Math.round((item.count / totalAttacks) * 100) : 0
    }))
}

function buildProtocolStats(attacks: AttackEvent[]): ProtocolStat[] {
  const counts = new Map<string, number>()
  for (const attack of attacks) {
    const key = attack.type
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return Array.from(counts.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6)
}

function buildScannerStats(attacks: AttackEvent[]): ScannerStat[] {
  if (attacks.length === 0) return []
  const counts = new Map<string, number>()
  for (const attack of attacks) {
    const raw = attack.scanner?.trim() ?? "Unidentified"
    const label = raw.length > 0 ? raw : "Unidentified"
    counts.set(label, (counts.get(label) ?? 0) + 1)
  }
  const total = attacks.length
  return Array.from(counts.entries())
    .map(([label, count]) => ({
      label,
      count,
      percentage: total > 0 ? (count / total) * 100 : 0,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
}

function humanizePattern(pattern: string): string {
  if (!pattern) return "Unknown"
  const trimmed = pattern.trim()
  if (!trimmed) return "Unknown"
  if (trimmed.toLowerCase() === "unknown") return "Unknown"
  return trimmed
    .replace(/[-_]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map(word => word[0]?.toUpperCase() + word.slice(1))
    .join(" ")
}

function buildPatternStats(attacks: AttackEvent[]): ScannerStat[] {
  if (attacks.length === 0) return []
  const counts = new Map<string, number>()
  for (const attack of attacks) {
    const normalized = attack.scanPattern?.trim() ?? "unknown"
    const key = normalized.length > 0 ? normalized.toLowerCase() : "unknown"
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  const total = attacks.length
  return Array.from(counts.entries())
    .map(([key, count]) => ({
      label: humanizePattern(key),
      count,
      percentage: total > 0 ? (count / total) * 100 : 0,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
}

function computeBrowserShare(attacks: AttackEvent[]): number {
  if (attacks.length === 0) return 0
  const browserLike = attacks.reduce((total, attack) => {
    return attack.isRealBrowser ? total + 1 : total
  }, 0)
  return browserLike / attacks.length
}

function computeAverageConfidence(attacks: AttackEvent[]): number | null {
  const values = attacks
    .map(attack => attack.toolConfidence)
    .filter((value): value is number => typeof value === "number" && Number.isFinite(value))

  if (values.length === 0) return null

  const total = values.reduce((sum, value) => sum + value, 0)
  return total / values.length
}

function buildTimelineBuckets(attacks: AttackEvent[]): TimelineBucket[] {
  const bucketSizeMs = 15 * 60 * 1000
  const buckets = new Map<number, number>()
  for (const attack of attacks) {
    const time = Date.parse(attack.timestamp)
    if (Number.isNaN(time)) continue
    const bucketStart = Math.floor(time / bucketSizeMs) * bucketSizeMs
    buckets.set(bucketStart, (buckets.get(bucketStart) ?? 0) + 1)
  }
  return Array.from(buckets.entries())
    .sort((a, b) => b[0] - a[0])
    .slice(0, 5)
    .map(([start, count]) => ({
      iso: new Date(start).toISOString(),
      label: new Date(start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      count
    }))
}

function buildThreatSummary(attacks: AttackEvent[]): SeveritySummary {
  const summary: SeveritySummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  }
  for (const attack of attacks) {
    summary[attack.severity] += 1
  }
  return summary
}

function collectHighSeverityPayloads(attacks: AttackEvent[]): string[] {
  const samples: string[] = []
  for (const attack of attacks) {
    if ((attack.severity === "high" || attack.severity === "critical") && attack.payload !== "—") {
      if (!samples.includes(attack.payload)) {
        const truncated = attack.payload.length > 140
          ? `${attack.payload.slice(0, 137)}…`
          : attack.payload
        samples.push(truncated)
      }
    }
    if (samples.length >= 3) break
  }
  return samples
}

function formatRelativeTime(timestamp: string): string {
  const parsed = Date.parse(timestamp)
  if (Number.isNaN(parsed)) return "Unknown"
  const diffMs = Date.now() - parsed
  const diffSeconds = Math.floor(diffMs / 1000)
  if (diffSeconds < 30) return "Just now"
  if (diffSeconds < 60) return `${diffSeconds}s ago`
  const diffMinutes = Math.floor(diffSeconds / 60)
  if (diffMinutes < 60) return `${diffMinutes} min ago`
  const diffHours = Math.floor(diffMinutes / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  if (diffDays === 1) return "1 day ago"
  return `${diffDays} days ago`
}

function severityVariant(severity: Severity): "destructive" | "default" | "secondary" {
  if (severity === "critical" || severity === "high") return "destructive"
  if (severity === "medium") return "default"
  return "secondary"
}

const LOG_ID_CANDIDATE_KEYS = [
  "log_id",
  "attacker_log_id",
  "original_log_id",
  "source_log_id",
  "related_log_id",
  "attacker_log_uuid"
] as const

function normalizeGeneratedByAI(value: unknown): boolean {
  if (typeof value === "boolean") return value
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase()
    if (["true", "1", "yes"].includes(normalized)) return true
    if (["false", "0", "no"].includes(normalized)) return false
  }
  if (typeof value === "number") return value !== 0
  if (value === null || typeof value === "undefined") return true
  return Boolean(value)
}

function extractLogIdsFromContext(context: GenericRecord | null): string[] {
  if (!context) return []
  const identifiers = new Set<string>()

  for (const key of LOG_ID_CANDIDATE_KEYS) {
    const candidate = getStringField(context, key)
    if (candidate) {
      identifiers.add(candidate)
    }
  }

  const metadata = ensureRecord(context["metadata"])
  if (metadata) {
    for (const key of LOG_ID_CANDIDATE_KEYS) {
      const candidate = getStringField(metadata, key)
      if (candidate) {
        identifiers.add(candidate)
      }
    }
  }

  const related = ensureRecord(context["related_log"])
  if (related) {
    const candidate = getStringField(related, "id") ?? getStringField(related, "log_id")
    if (candidate) {
      identifiers.add(candidate)
    }
  }

  const relatedLogs = context["related_logs"]
  if (Array.isArray(relatedLogs)) {
    for (const entry of relatedLogs) {
      if (typeof entry === "string") {
        identifiers.add(entry)
      } else {
        const record = ensureRecord(entry)
        if (record) {
          const candidate = getStringField(record, "id") ?? getStringField(record, "log_id")
          if (candidate) {
            identifiers.add(candidate)
          }
        }
      }
    }
  }

  return Array.from(identifiers)
}

function parseAnalysisRulesFromContext(context: GenericRecord | null): string[] {
  if (!context) return []
  const rawRules = context["analysis_rules_triggered"]
  if (!rawRules) return []

  const toStringValue = (value: unknown): string | null => {
    if (typeof value === "string") return value
    if (typeof value === "number") return value.toString()
    if (value && typeof value === "object") {
      try {
        return JSON.stringify(value)
      } catch {
        return null
      }
    }
    return null
  }

  if (Array.isArray(rawRules)) {
    return rawRules
      .map(toStringValue)
      .filter((value): value is string => Boolean(value && value.trim()))
      .map(value => value.trim())
  }

  if (typeof rawRules === "string") {
    try {
      const parsed = JSON.parse(rawRules) as unknown
      if (Array.isArray(parsed)) {
        return parsed
          .map(toStringValue)
          .filter((value): value is string => Boolean(value && value.trim()))
          .map(value => value.trim())
      }
    } catch {
      if (rawRules.trim()) {
        return [rawRules.trim()]
      }
    }
    if (rawRules.trim()) {
      return [rawRules.trim()]
    }
  }

  return []
}

function resolveRelatedLogId(
  sourceIp: string | undefined,
  generatedTimestamp: string | undefined,
  honeypotType: string | undefined,
  attacks: AttackEvent[],
  directIds: string[]
): string | null {
  for (const identifier of directIds) {
    if (attacks.some(attack => attack.id === identifier)) {
      return identifier
    }
  }

  if (directIds.length > 0) {
    return directIds[0]
  }

  if (!sourceIp) {
    return null
  }

  const normalizedIp = sourceIp.trim()
  if (!normalizedIp) {
    return null
  }

  const normalizedHoneypot = honeypotType ? honeypotType.toLowerCase() : undefined

  const matchingAttacks = attacks.filter(attack => {
    if (attack.ip !== normalizedIp) {
      return false
    }
    if (!normalizedHoneypot) {
      return true
    }
    return attack.type.toLowerCase().includes(normalizedHoneypot)
  })

  if (matchingAttacks.length === 0) {
    return null
  }

  if (generatedTimestamp) {
    const targetTime = Date.parse(generatedTimestamp)
    if (!Number.isNaN(targetTime)) {
      let closest: AttackEvent | null = null
      let smallestDiff = Number.POSITIVE_INFINITY
      for (const attack of matchingAttacks) {
        const attackTime = Date.parse(attack.timestamp)
        if (Number.isNaN(attackTime)) {
          continue
        }
        const diff = Math.abs(attackTime - targetTime)
        if (diff < smallestDiff) {
          smallestDiff = diff
          closest = attack
        }
      }
      if (closest && smallestDiff <= LOG_MATCH_WINDOW_MS) {
        return closest.id
      }
    }
  }

  return matchingAttacks[0]?.id ?? null
}

function normalizeDisinformationRecord(
  raw: GenericRecord,
  attacks: AttackEvent[]
): DisinformationEntry | null {
  const id = getStringField(raw, "id")
  const content = getStringField(raw, "content")
  if (!id || !content) {
    return null
  }

  const timestampValue = getStringField(raw, "creation_timestamp")
    ?? getStringField(raw, "created_at")
    ?? getStringField(raw, "inserted_at")

  const createdAt = (() => {
    if (timestampValue) {
      const parsed = Date.parse(timestampValue)
      if (!Number.isNaN(parsed)) {
        return new Date(parsed).toISOString()
      }
    }
    return new Date().toISOString()
  })()

  const contentType = getStringField(raw, "content_type") ?? "text/plain"
  const aiModel = getStringField(raw, "ai_model") ?? undefined
  const generatedByAI = normalizeGeneratedByAI(raw["generated_by_ai"])

  const targetContext = ensureRecord(raw["target_context"])
  const sourceIp = targetContext ? getStringField(targetContext, "source_ip") : undefined
  const generatedTimestamp = targetContext ? getStringField(targetContext, "generated_timestamp") : undefined
  const honeypotType = targetContext ? getStringField(targetContext, "honeypot_type") : undefined
  const analysisTriggeredBy = targetContext ? getStringField(targetContext, "analysis_triggered_by") : undefined
  const analysisRules = parseAnalysisRulesFromContext(targetContext)
  const contextLogIds = extractLogIdsFromContext(targetContext)

  const relatedLogId = resolveRelatedLogId(
    sourceIp,
    generatedTimestamp,
    honeypotType,
    attacks,
    contextLogIds
  )

  return {
    id,
    createdAt,
    content,
    contentType,
    aiModel,
    generatedByAI,
    targetContext,
    relatedLogId,
    sourceIp: sourceIp ?? undefined,
    generatedTimestamp: generatedTimestamp ?? undefined,
    honeypotType: honeypotType ?? undefined,
    analysisTriggeredBy: analysisTriggeredBy ?? undefined,
    analysisRules: analysisRules.length > 0 ? analysisRules : undefined,
    contextLogIds
  }
}

export default function Page() {
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)
  const [threatData, setThreatData] = useState<ThreatData>({
    activeThreats: 0,
    blockedAttempts: 0,
    honeypotStatus: "connecting",
    connectedAttackers: 0
  })
  const [recentAttacks, setRecentAttacks] = useState<AttackEvent[]>([])
  const [topCountries, setTopCountries] = useState<CountryStat[]>([])
  const [protocolStats, setProtocolStats] = useState<ProtocolStat[]>([])
  const [timelineBuckets, setTimelineBuckets] = useState<TimelineBucket[]>([])
  const [severitySummary, setSeveritySummary] = useState<SeveritySummary>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  })
  const [highSeveritySamples, setHighSeveritySamples] = useState<string[]>([]
  const [scannerStats, setScannerStats] = useState<ScannerStat[]>([])
  const [patternStats, setPatternStats] = useState<ScannerStat[]>([])
  const [browserShare, setBrowserShare] = useState<number>(0)
  const [averageConfidence, setAverageConfidence] = useState<number | null>(null)

  const [disinformationEntries, setDisinformationEntries] = useState<DisinformationEntry[]>([])

  const [isConnected, setIsConnected] = useState(false)

  const isMountedRef = useRef(false)
  const channelRef = useRef<RealtimeChannel | null>(null)
  const disinformationChannelRef = useRef<RealtimeChannel | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const heartbeatIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const lastHeartbeatRef = useRef<number>(Date.now())
  const allAttacksRef = useRef<AttackEvent[]>([])
  const totalEventCountRef = useRef<number>(0)

  useEffect(() => {
    isMountedRef.current = true
    return () => {
      isMountedRef.current = false
    }
  }, [])

  const updateDisinformationEntries = useCallback((updater: (prev: DisinformationEntry[]) => DisinformationEntry[]) => {
    setDisinformationEntries(prev => {
      const next = updater(prev)
      return next === prev ? prev : next
    })
  }, [])

  const updateHoneypotStatus = useCallback((status: ThreatData["honeypotStatus"]) => {
    if (!isMountedRef.current) return
    setThreatData(prev => (
      prev.honeypotStatus === status
        ? prev
        : { ...prev, honeypotStatus: status }
    ))
  }, [])

  const processDisinformationRecords = useCallback(
    (records: GenericRecord[], attacks: AttackEvent[]): DisinformationEntry[] => {
      return records
        .map(item => normalizeDisinformationRecord(item, attacks))
        .filter((entry): entry is DisinformationEntry => Boolean(entry))
        .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    },
    []
  )

  const fetchDisinformationEntries = useCallback(async () => {
    try {
      const response = await supabase
        .from("disinformation_content")
        .select("*")
        .order("creation_timestamp", { ascending: false })
        .limit(MAX_STORED_DISINFORMATION)

      if (response.error) {
        console.error("Failed to load disinformation content", response.error)
        return
      }

      const processed = processDisinformationRecords(
        (response.data ?? []) as GenericRecord[],
        allAttacksRef.current
      )

      if (!isMountedRef.current) return

      updateDisinformationEntries(() => processed.slice(0, MAX_STORED_DISINFORMATION))
    } catch (error) {
      console.error("Unexpected error while loading disinformation content", error)
    }
  }, [processDisinformationRecords, updateDisinformationEntries])

  const applyAttackData = useCallback((attacks: AttackEvent[], totalCount: number, lastTimestamp?: string) => {
    if (!isMountedRef.current) return

    const sortedAttacks = attacks
      .slice(0, MAX_STORED_EVENTS)
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))

    allAttacksRef.current = sortedAttacks
    totalEventCountRef.current = totalCount

    const uniqueIps = new Set(sortedAttacks.map(attack => attack.ip || "Unknown"))

    setRecentAttacks(sortedAttacks.slice(0, 20))
    setTopCountries(buildTopCountryStats(sortedAttacks))
    setProtocolStats(buildProtocolStats(sortedAttacks))
    setTimelineBuckets(buildTimelineBuckets(sortedAttacks))
    setSeveritySummary(buildThreatSummary(sortedAttacks))
    setHighSeveritySamples(collectHighSeverityPayloads(sortedAttacks))
    setScannerStats(buildScannerStats(sortedAttacks))
    setPatternStats(buildPatternStats(sortedAttacks))
    setBrowserShare(computeBrowserShare(sortedAttacks))
    setAverageConfidence(computeAverageConfidence(sortedAttacks))
    setThreatData(prev => ({
      ...prev,
      activeThreats: computeActiveThreats(sortedAttacks),
      blockedAttempts: totalCount,
      connectedAttackers: uniqueIps.size
    }))

    updateDisinformationEntries(prev => {
      if (prev.length === 0) {
        return prev
      }

      let changed = false
      const updated = prev.map(entry => {
        const resolved = resolveRelatedLogId(
          entry.sourceIp,
          entry.generatedTimestamp,
          entry.honeypotType,
          sortedAttacks,
          entry.contextLogIds
        )

        if (resolved === entry.relatedLogId) {
          return entry
        }

        changed = true
        return { ...entry, relatedLogId: resolved }
      })

      return changed ? updated : prev
    })

    const candidateTimestamp = lastTimestamp ?? sortedAttacks[0]?.timestamp
    if (candidateTimestamp) {
      const parsed = Date.parse(candidateTimestamp)
      setLastUpdate(Number.isNaN(parsed) ? new Date() : new Date(parsed))
    } else {
      setLastUpdate(new Date())
    }
  }, [updateDisinformationEntries])

  const fetchLatestData = useCallback(async () => {
    try {
      const [eventsResponse, countResponse] = await Promise.all([
        supabase
          .from("attacker_logs")
          .select("*")
          .order("timestamp", { ascending: false })
          .limit(MAX_STORED_EVENTS),
        supabase
          .from("attacker_logs")
          .select("*", { count: "exact", head: true })
      ])

      if (eventsResponse.error) {
        console.error("Failed to load attacker logs", eventsResponse.error)
        return
      }

      if (countResponse.error) {
        console.error("Failed to load attacker log count", countResponse.error)
      }

      const normalized = (eventsResponse.data ?? [])
        .map(item => normalizeAttackRecord(item as GenericRecord))
        .filter((attack): attack is AttackEvent => Boolean(attack))

      const totalCount = typeof countResponse.count === "number"
        ? countResponse.count
        : normalized.length

      applyAttackData(normalized, totalCount)
      lastHeartbeatRef.current = Date.now()
    } catch (error) {
      console.error("Unexpected error while loading attacker logs", error)
    }
  }, [applyAttackData])

  const handleRefresh = useCallback(async () => {
    setIsRefreshing(true)
    try {
      await Promise.all([fetchLatestData(), fetchDisinformationEntries()])
    } finally {
      setIsRefreshing(false)
    }
  }, [fetchLatestData, fetchDisinformationEntries])

  useEffect(() => {
    let cancelled = false

    const subscribeToRealtime = () => {
      if (cancelled) return
      if (channelRef.current) {
        supabase.removeChannel(channelRef.current)
        channelRef.current = null
      }

      updateHoneypotStatus("connecting")
      setIsConnected(false)
      lastHeartbeatRef.current = Date.now()

      const channel = supabase.channel("public:attacker_logs")
      channelRef.current = channel

      channel.on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "attacker_logs" },
        (payload: RealtimePostgresInsertPayload<GenericRecord>) => {
          if (cancelled || !isMountedRef.current) return
          const attack = normalizeAttackRecord(payload.new)
          if (!attack) return

          const alreadyKnown = allAttacksRef.current.some(existing => existing.id === attack.id)
          if (alreadyKnown) return

          const nextTotal = totalEventCountRef.current + 1
          const combined = [attack, ...allAttacksRef.current]
          applyAttackData(combined, nextTotal, attack.timestamp)
          lastHeartbeatRef.current = Date.now()
        }
      )

      channel.subscribe(status => {
        if (cancelled || !isMountedRef.current) return
        if (status === "SUBSCRIBED") {
          setIsConnected(true)
          updateHoneypotStatus("active")
          lastHeartbeatRef.current = Date.now()
          void fetchLatestData()
        } else if (status === "CHANNEL_ERROR" || status === "CLOSED" || status === "TIMED_OUT") {
          setIsConnected(false)
          updateHoneypotStatus("reconnecting")
          if (!reconnectTimeoutRef.current) {
            reconnectTimeoutRef.current = setTimeout(() => {
              reconnectTimeoutRef.current = null
              subscribeToRealtime()
            }, 3000)
          }
        }
      })
    }

    const startHeartbeat = () => {
      if (heartbeatIntervalRef.current) {
        clearInterval(heartbeatIntervalRef.current)
      }

      heartbeatIntervalRef.current = setInterval(() => {
        if (cancelled) return
        const channel = channelRef.current
        if (!channel) {
          if (!reconnectTimeoutRef.current) {
            updateHoneypotStatus("reconnecting")
            reconnectTimeoutRef.current = setTimeout(() => {
              reconnectTimeoutRef.current = null
              subscribeToRealtime()
            }, 2000)
          }
          return
        }

        if ((channel as RealtimeChannel).state !== "joined") {
          setIsConnected(false)
          updateHoneypotStatus("reconnecting")
          if (!reconnectTimeoutRef.current) {
            reconnectTimeoutRef.current = setTimeout(() => {
              reconnectTimeoutRef.current = null
              subscribeToRealtime()
            }, 2000)
          }
          return
        }

        const now = Date.now()
        if (now - lastHeartbeatRef.current > 60000) {
          setIsConnected(false)
          updateHoneypotStatus("reconnecting")
          if (!reconnectTimeoutRef.current) {
            reconnectTimeoutRef.current = setTimeout(() => {
              reconnectTimeoutRef.current = null
              subscribeToRealtime()
            }, 2000)
          }
          return
        }

        channel
          .send({ type: "broadcast", event: "heartbeat", payload: { timestamp: now } })
          .then(result => {
            if (cancelled) return
            if (result !== "ok") {
              setIsConnected(false)
              updateHoneypotStatus("reconnecting")
              if (!reconnectTimeoutRef.current) {
                reconnectTimeoutRef.current = setTimeout(() => {
                  reconnectTimeoutRef.current = null
                  subscribeToRealtime()
                }, 2000)
              }
            } else {
              lastHeartbeatRef.current = now
            }
          })
          .catch(error => {
            if (cancelled) return
            console.warn("Heartbeat failed, attempting resubscribe", error)
            setIsConnected(false)
            updateHoneypotStatus("reconnecting")
            if (!reconnectTimeoutRef.current) {
              reconnectTimeoutRef.current = setTimeout(() => {
                reconnectTimeoutRef.current = null
                subscribeToRealtime()
              }, 2000)
            }
          })
      }, 20000)
    }

    fetchLatestData()
    subscribeToRealtime()
    startHeartbeat()

    return () => {
      cancelled = true
      if (heartbeatIntervalRef.current) {
        clearInterval(heartbeatIntervalRef.current)
        heartbeatIntervalRef.current = null
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
        reconnectTimeoutRef.current = null
      }
      if (channelRef.current) {
        supabase.removeChannel(channelRef.current)
        channelRef.current = null
      }
    }
  }, [applyAttackData, fetchLatestData, updateHoneypotStatus])

  useEffect(() => {
    let cancelled = false

    const ingestRecord = (record: GenericRecord) => {
      const normalized = processDisinformationRecords([record], allAttacksRef.current)
      if (normalized.length === 0) return
      const [entry] = normalized

      updateDisinformationEntries(prev => {
        const existingIndex = prev.findIndex(item => item.id === entry.id)
        if (existingIndex >= 0) {
          const next = prev.slice()
          next[existingIndex] = entry
          next.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
          return next
        }

        const next = [entry, ...prev]
        next.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
        return next.slice(0, MAX_STORED_DISINFORMATION)
      })
    }

    void fetchDisinformationEntries()

    if (disinformationChannelRef.current) {
      supabase.removeChannel(disinformationChannelRef.current)
      disinformationChannelRef.current = null
    }

    const channel = supabase.channel("public:disinformation_content")
    disinformationChannelRef.current = channel

    channel.on(
      "postgres_changes",
      { event: "INSERT", schema: "public", table: "disinformation_content" },
      (payload: RealtimePostgresInsertPayload<GenericRecord>) => {
        if (cancelled || !isMountedRef.current) return
        ingestRecord(payload.new)
      }
    )

    channel.on(
      "postgres_changes",
      { event: "UPDATE", schema: "public", table: "disinformation_content" },
      (payload: RealtimePostgresInsertPayload<GenericRecord>) => {
        if (cancelled || !isMountedRef.current) return
        ingestRecord(payload.new)
      }
    )

    channel.subscribe()

    return () => {
      cancelled = true
      if (disinformationChannelRef.current) {
        supabase.removeChannel(disinformationChannelRef.current)
        disinformationChannelRef.current = null
      }
    }
  }, [fetchDisinformationEntries, processDisinformationRecords, updateDisinformationEntries])

  const connectionLabel = isConnected
    ? "Live"
    : threatData.honeypotStatus === "reconnecting"
      ? "Reconnecting"
      : "Connecting..."

  const connectionBadgeClass = isConnected ? "text-green-600" : "text-orange-600"

  const highSeverityCount = severitySummary.high + severitySummary.critical
  const protocolTotal = protocolStats.reduce((total, stat) => total + stat.count, 0)
  const maxTimelineCount = timelineBuckets.reduce((max, bucket) => Math.max(max, bucket.count), 0)
  const scannerTotal = scannerStats.reduce((total, stat) => total + stat.count, 0)
  const patternTotal = patternStats.reduce((total, stat) => total + stat.count, 0)
  const browserPercentage = Math.round(Math.min(Math.max(browserShare, 0), 1) * 100)
  const automationPercentage = 100 - browserPercentage
  const averageConfidencePercentage = averageConfidence !== null
    ? Math.round(Math.min(Math.max(averageConfidence, 0), 1) * 100)
    : null

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
                    Security Dashboard
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem>
                  <BreadcrumbPage>Live Monitor</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
          <div className="ml-auto flex items-center gap-2 px-4">
            <Badge variant="outline" className={connectionBadgeClass}>
              <Activity className={`w-3 h-3 mr-1 ${isConnected ? "animate-pulse" : ""}`} />
              {connectionLabel}
            </Badge>
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={isRefreshing}
            >
              <RefreshCw className={`w-4 h-4 mr-1 ${isRefreshing ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>
        </header>

        <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
          <Alert className={isConnected ? "border-green-200 bg-green-50" : "border-orange-200 bg-orange-50"}>
            <Shield className={`h-4 w-4 ${isConnected ? "text-green-600" : "text-orange-600"}`} />
            <AlertDescription className={isConnected ? "text-green-800" : "text-orange-800"}>
              {isConnected
                ? `All honeypot services are operational. Last updated: ${lastUpdate ? lastUpdate.toLocaleTimeString() : "—"}`
                : "Establishing connection to honeypot network..."}
            </AlertDescription>
          </Alert>

          <div className="grid auto-rows-min gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600 font-mono">{threatData.activeThreats}</div>
                <p className="text-xs text-muted-foreground">
                  Observed within last {ACTIVE_WINDOW_MINUTES} minutes
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Captured Events</CardTitle>
                <Shield className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600 font-mono">{threatData.blockedAttempts.toLocaleString()}</div>
                <p className="text-xs text-muted-foreground">Total honeypot interactions recorded</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Unique Attackers</CardTitle>
                <Users className="h-4 w-4 text-orange-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-600 font-mono">{threatData.connectedAttackers}</div>
                <p className="text-xs text-muted-foreground">Distinct source IPs observed</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Honeypot Status</CardTitle>
                <Server className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-blue-600 capitalize">{threatData.honeypotStatus}</div>
                <p className="text-xs text-muted-foreground">
                  {isConnected ? "Realtime feed established" : "Waiting for live telemetry"}
                </p>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-4 md:grid-cols-4">
            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Real-time Attack Feed
                  <Badge variant="secondary" className="ml-2">
                    {recentAttacks.length} events
                  </Badge>
                </CardTitle>
                <CardDescription>Live monitoring of incoming threats</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  <div className="space-y-3">
                    {recentAttacks.length > 0 ? recentAttacks.map((attack) => (
                      <div
                        id={`attack-${attack.id}`}
                        key={attack.id}
                        className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors scroll-mt-24"
                      >
                        <div className="flex items-center gap-3">
                          <Badge variant={severityVariant(attack.severity)}>
                            {severityLabelMap[attack.severity]}
                          </Badge>
                          <div>
                            <p className="font-medium">{attack.type}</p>
                            <p className="text-sm text-muted-foreground font-mono">
                              {attack.ip}{attack.port !== "—" ? `:${attack.port}` : ""} • {attack.country}
                            </p>
                            <div className="mt-1 flex flex-wrap items-center gap-2">
                              {attack.scanPattern !== "unknown" && (
                                <Badge variant="outline" className="text-[10px] uppercase tracking-wide">
                                  {humanizePattern(attack.scanPattern)}
                                </Badge>
                              )}
                              {attack.toolConfidence !== null && (
                                <span className="text-xs text-muted-foreground font-mono">
                                  {Math.round(Math.min(Math.max(attack.toolConfidence, 0), 1) * 100)}% confidence
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-muted-foreground flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatRelativeTime(attack.timestamp)}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-1" title={attack.userAgent}>
                            {attack.userAgent}
                          </p>
                        </div>
                      </div>
                    )) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <Zap className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p>Waiting for attack data...</p>
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Attack Origins
                </CardTitle>
                <CardDescription>Top attacking countries (last 24h)</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {topCountries.length > 0 ? topCountries.map((country, index) => (
                    <div key={index} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <MapPin className="h-4 w-4" />
                          <span className="font-medium">{country.country}</span>
                        </div>
                        <span className="text-sm text-muted-foreground font-mono">{country.attacks}</span>
                      </div>
                      <Progress value={Math.min(country.percentage, 100)} className="h-2" />
                    </div>
                  )) : (
                    <p className="text-sm text-muted-foreground text-center py-6">No geographic data available yet.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Radar className="h-5 w-5" />
                  Scanner Insights
                </CardTitle>
                <CardDescription>Automation signals from recent honeypot hits</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <p className="text-xs uppercase text-muted-foreground mb-1">Automation share</p>
                    <div className="flex items-center gap-2">
                      <Progress value={automationPercentage} className="h-2 flex-1" />
                      <span className="text-sm font-mono">{automationPercentage}%</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      Browser-like traffic: {browserPercentage}%
                    </p>
                  </div>

                  <div>
                    <p className="text-xs uppercase text-muted-foreground mb-1">Avg. tool confidence</p>
                    {averageConfidencePercentage !== null ? (
                      <div className="flex items-center gap-2">
                        <Progress value={averageConfidencePercentage} className="h-2 flex-1" />
                        <span className="text-sm font-mono">{averageConfidencePercentage}%</span>
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground">Not enough data yet.</p>
                    )}
                  </div>

                  <div>
                    <p className="text-xs uppercase text-muted-foreground mb-2">Top scanners</p>
                    {scannerStats.length > 0 ? (
                      <div className="space-y-2">
                        {scannerStats.map(scanner => (
                          <div key={scanner.label} className="flex items-center justify-between">
                            <span className="text-sm font-medium">{scanner.label}</span>
                            <span className="text-xs text-muted-foreground font-mono">
                              {scanner.count}{scannerTotal > 0 ? ` · ${Math.round(scanner.percentage)}%` : ""}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground">Awaiting scanner telemetry.</p>
                    )}
                  </div>

                  <div>
                    <p className="text-xs uppercase text-muted-foreground mb-2">Scan patterns</p>
                    {patternStats.length > 0 ? (
                      <div className="space-y-2">
                        {patternStats.map(pattern => (
                          <div key={pattern.label} className="flex items-center justify-between">
                            <span className="text-sm">{pattern.label}</span>
                            <span className="text-xs text-muted-foreground font-mono">
                              {pattern.count}{patternTotal > 0 ? ` · ${Math.round(pattern.percentage)}%` : ""}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground">No pattern classification yet.</p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardContent className="p-6">
              <Tabs defaultValue="network" className="w-full">
                <TabsList className="grid w-full grid-cols-5">
                  <TabsTrigger value="network">Network Activity</TabsTrigger>
                  <TabsTrigger value="protocols">Protocols</TabsTrigger>
                  <TabsTrigger value="payloads">Payloads</TabsTrigger>
                  <TabsTrigger value="timeline">Timeline</TabsTrigger>
                  <TabsTrigger value="disinformation">Disinformation</TabsTrigger>
                </TabsList>

                <TabsContent value="network" className="mt-4">
                  <div className="space-y-4">
                    <div className="grid grid-cols-3 gap-4">
                      <div className="text-center p-4 border rounded">
                        <p className="text-2xl font-bold">{threatData.activeThreats}</p>
                        <p className="text-sm text-muted-foreground">Active (last {ACTIVE_WINDOW_MINUTES}m)</p>
                      </div>
                      <div className="text-center p-4 border rounded">
                        <p className="text-2xl font-bold">{threatData.blockedAttempts}</p>
                        <p className="text-sm text-muted-foreground">Total events captured</p>
                      </div>
                      <div className="text-center p-4 border rounded">
                        <p className="text-2xl font-bold">{threatData.connectedAttackers}</p>
                        <p className="text-sm text-muted-foreground">Unique attacker IPs</p>
                      </div>
                    </div>
                    <div className="flex justify-around text-center">
                      {(["critical", "high", "medium", "low"] as Severity[]).map(level => (
                        <div key={level}>
                          <p className="text-lg font-semibold">{severitySummary[level]}</p>
                          <p className="text-xs uppercase text-muted-foreground">{severityLabelMap[level]}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="protocols" className="mt-4">
                  <div className="space-y-3">
                    {protocolStats.length > 0 ? protocolStats.map(protocol => (
                      <div key={protocol.type} className="flex justify-between items-center p-3 border rounded">
                        <span className="font-medium">{protocol.type}</span>
                        <div className="flex items-center gap-2">
                          <Progress value={protocolTotal > 0 ? (protocol.count / protocolTotal) * 100 : 0} className="w-24 h-2" />
                          <span className="text-sm text-muted-foreground font-mono">{protocol.count}</span>
                        </div>
                      </div>
                    )) : (
                      <p className="text-sm text-muted-foreground text-center py-6">No protocol activity captured yet.</p>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="payloads" className="mt-4">
                  <div className="space-y-3">
                    <Alert>
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription>
                        {highSeverityCount} high-risk payloads detected across recent events
                      </AlertDescription>
                    </Alert>
                    <div className="space-y-2">
                      {highSeveritySamples.length > 0 ? highSeveritySamples.map((sample, index) => (
                        <div key={index} className="p-3 border rounded bg-muted/30">
                          <code className="text-xs break-words">{sample}</code>
                        </div>
                      )) : (
                        <p className="text-sm text-muted-foreground text-center py-6">No high-risk payloads observed yet.</p>
                      )}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="timeline" className="mt-4">
                  <div className="space-y-3">
                    {timelineBuckets.length > 0 ? timelineBuckets.map(bucket => (
                      <div key={bucket.iso} className="flex items-center gap-4 p-3 border rounded">
                        <div className="text-sm text-muted-foreground font-mono">
                          {bucket.label}
                        </div>
                        <Badge variant="outline">
                          {bucket.count} events
                        </Badge>
                        <div className="flex-1">
                          <Progress value={maxTimelineCount > 0 ? (bucket.count / maxTimelineCount) * 100 : 0} className="h-2" />
                        </div>
                      </div>
                    )) : (
                      <p className="text-sm text-muted-foreground text-center py-6">Timeline will populate as events arrive.</p>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="disinformation" className="mt-4">
                  <DisinformationList entries={disinformationEntries} />
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
