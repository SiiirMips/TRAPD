"use client"

import { ScrollArea } from "@/components/ui/scroll-area"
import { DisinformationCard } from "./disinformation-card"
import type { DisinformationEntry } from "./types"

interface DisinformationListProps {
  entries: DisinformationEntry[]
}

export function DisinformationList({ entries }: DisinformationListProps) {
  if (entries.length === 0) {
    return (
      <div className="rounded-lg border bg-muted/30 p-6 text-center text-sm text-muted-foreground">
        No AI deception responses have been generated yet. They will appear here in real-time once available.
      </div>
    )
  }

  return (
    <ScrollArea className="max-h-[420px] pr-4">
      <div className="space-y-4">
        {entries.map(entry => (
          <DisinformationCard key={entry.id} entry={entry} />
        ))}
      </div>
    </ScrollArea>
  )
}
