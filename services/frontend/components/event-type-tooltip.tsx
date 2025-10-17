import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

const eventTypeDescriptions: Record<string, string> = {
  port_scan: "Portscan detected",
  brute_force: "Brute force login attempt",
  dos: "Denial of Service",
  malware: "Malware activity",
  intrusion: "Intrusion attempt",
};

export function EventTypeTooltip({ eventType }: { eventType: string }) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span>{eventType}</span>
        </TooltipTrigger>
        <TooltipContent>
          {eventTypeDescriptions[eventType] || "No description"}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
