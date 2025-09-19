"use client"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from "@/components/ui/card"
import type { DisinformationEntry } from "./types"
import { Clock, Link2, Sparkles } from "lucide-react"

interface DisinformationCardProps {
  entry: DisinformationEntry
}

function formatTimestamp(value?: string): string | undefined {
  if (!value) return undefined
  const parsed = Date.parse(value)
  if (Number.isNaN(parsed)) {
    return value
  }
  return new Date(parsed).toLocaleString()
}

function hasContextData(context: Record<string, unknown> | null): boolean {
  if (!context) return false
  return Object.keys(context).length > 0
}

function normalizeRules(rules: string[] | undefined): string[] {
  if (!rules || rules.length === 0) {
    return []
  }
  const seen = new Set<string>()
  const normalized: string[] = []
  for (const rule of rules) {
    const trimmed = rule.trim()
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed)
      normalized.push(trimmed)
    }
  }
  return normalized
}

export function DisinformationCard({ entry }: DisinformationCardProps) {
  const createdAtLabel = formatTimestamp(entry.createdAt) ?? entry.createdAt
  const generatedAtLabel = formatTimestamp(entry.generatedTimestamp) ?? createdAtLabel
  const sourceIp = entry.sourceIp ?? "Unknown"
  const analysisRules = normalizeRules(entry.analysisRules)
  const contextAvailable = hasContextData(entry.targetContext)

  return (
    <Card>
      <CardHeader className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <Sparkles className="h-4 w-4 text-purple-500" />
            AI deception response
          </CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            {entry.honeypotType ? (
              <Badge variant="outline" className="uppercase tracking-wide">
                {entry.honeypotType}
              </Badge>
            ) : null}
            <Badge
              variant="secondary"
              className={entry.generatedByAI ? "bg-purple-100 text-purple-700" : undefined}
            >
              {entry.generatedByAI ? "AI generated" : "Manual"}
            </Badge>
          </div>
        </div>
        <CardDescription className="flex flex-wrap items-center gap-2 text-xs sm:text-sm">
          <Clock className="h-3.5 w-3.5" />
          {createdAtLabel}
          {entry.aiModel ? (
            <>
              <span className="text-muted-foreground">•</span>
              Model: {entry.aiModel}
            </>
          ) : null}
          {entry.analysisTriggeredBy ? (
            <>
              <span className="text-muted-foreground">•</span>
              Trigger: {entry.analysisTriggeredBy}
            </>
          ) : null}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="whitespace-pre-wrap rounded-lg border bg-background/80 p-4 text-sm leading-relaxed shadow-sm">
          {entry.content}
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <MetadataItem label="Content type" value={entry.contentType} />
          <MetadataItem label="Source IP" value={sourceIp} monospace />
          <MetadataItem label="Generated at" value={generatedAtLabel} />
          {entry.analysisTriggeredBy ? (
            <MetadataItem label="Analysis trigger" value={entry.analysisTriggeredBy} />
          ) : null}
        </div>
        {analysisRules.length > 0 ? (
          <div>
            <p className="text-xs font-semibold uppercase text-muted-foreground">
              Analysis rules triggered
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {analysisRules.map(rule => (
                <Badge key={rule} variant="outline" className="text-xs">
                  {rule}
                </Badge>
              ))}
            </div>
          </div>
        ) : null}
        {contextAvailable ? (
          <details className="group rounded-lg border bg-muted/30 p-3 text-xs leading-relaxed">
            <summary className="cursor-pointer list-none text-sm font-medium text-foreground">
              View raw target context
            </summary>
            <pre className="mt-3 max-h-60 overflow-auto whitespace-pre-wrap break-words text-[11px] text-foreground">
              {JSON.stringify(entry.targetContext, null, 2)}
            </pre>
          </details>
        ) : null}
      </CardContent>
      <CardFooter className="flex flex-wrap items-center justify-between gap-2 border-t pt-4">
        <div className="text-xs text-muted-foreground">
          {entry.relatedLogId ? (
            <>
              Linked log:
              {" "}
              <span className="font-mono text-foreground">{entry.relatedLogId}</span>
            </>
          ) : (
            "No related log identified yet"
          )}
        </div>
        {entry.relatedLogId ? (
          <Button variant="outline" size="sm" asChild>
            <a href={`#attack-${entry.relatedLogId}`} className="flex items-center gap-1">
              <Link2 className="h-4 w-4" />
              Jump to log
            </a>
          </Button>
        ) : null}
      </CardFooter>
    </Card>
  )
}

interface MetadataItemProps {
  label: string
  value?: string
  monospace?: boolean
}

function MetadataItem({ label, value, monospace }: MetadataItemProps) {
  if (!value) {
    return null
  }

  return (
    <div className="rounded-lg border bg-muted/30 px-3 py-2">
      <p className="text-xs font-medium uppercase text-muted-foreground">{label}</p>
      <p className={monospace ? "text-sm font-mono" : "text-sm"}>{value}</p>
    </div>
  )
}
