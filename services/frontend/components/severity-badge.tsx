import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const severityColor: Record<string, string> = {
  LOW: "bg-gray-200 text-gray-800 border-gray-300",
  MEDIUM: "bg-yellow-100 text-yellow-800 border-yellow-200",
  HIGH: "bg-orange-100 text-orange-800 border-orange-200",
  CRITICAL: "bg-red-500 text-white border-red-500",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge className={cn("px-2", severityColor[severity] || severityColor.LOW)}>
      {severity}
    </Badge>
  );
}
