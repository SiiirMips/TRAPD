export type DisinformationEntry = {
  id: string
  createdAt: string
  content: string
  contentType: string
  aiModel?: string
  generatedByAI: boolean
  targetContext: Record<string, unknown> | null
  relatedLogId: string | null
  sourceIp?: string
  generatedTimestamp?: string
  honeypotType?: string
  analysisTriggeredBy?: string
  analysisRules?: string[]
  contextLogIds: string[]
}
