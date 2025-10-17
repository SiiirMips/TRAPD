'use client';

import * as React from 'react';
import useSWR from 'swr';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { SeverityBadge } from '@/components/severity-badge';
import { EventTypeTooltip } from '@/components/event-type-tooltip';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';

interface Event {
  id: number;
  ts: string;
  sensor_id: string;
  src_ip: string;
  dst_port: number;
  proto: string;
  severity: string;
  event_type: string;
}

interface EventsResponse {
  events: Event[];
  total: number;
}

const fetcher = (url: string) => fetch(url).then((res) => res.json());


export function LiveFeed({ ipPort, severity, sensorId }: { ipPort: string; severity: string; sensorId: string }) {
  // Build query string
  const queryParams = new URLSearchParams({
    limit: '200',
    ...(ipPort && { ipPort }),
    ...(severity && { severity }),
    ...(sensorId && { sensorId }),
  });

  const { data, error, isLoading } = useSWR<EventsResponse>(
    `/api/events?${queryParams.toString()}`,
    fetcher,
    {
      refreshInterval: 5000, // Poll every 5 seconds
      revalidateOnFocus: true,
    }
  );

  const formatTimestamp = (ts: string) => {
    const date = new Date(ts);
    return date.toLocaleString('de-DE', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Table with ScrollArea */}
      <ScrollArea className="h-[60vh] rounded-md border">
        {isLoading ? (
          <div className="p-4 space-y-3">
            {Array.from({ length: 10 }).map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        ) : error || !data ? (
          <div className="flex items-center justify-center h-full p-8">
            <p className="text-sm text-muted-foreground">
              Failed to load events
            </p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[180px]">Timestamp</TableHead>
                <TableHead className="w-[120px]">Sensor ID</TableHead>
                <TableHead className="w-[140px]">Source IP</TableHead>
                <TableHead className="w-[100px]">Dest Port</TableHead>
                <TableHead className="w-[80px]">Protocol</TableHead>
                <TableHead className="w-[100px]">Severity</TableHead>
                <TableHead>Event Type</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.events.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8">
                    <p className="text-sm text-muted-foreground">
                      No events found
                    </p>
                  </TableCell>
                </TableRow>
              ) : (
                data.events.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="font-mono text-xs">
                      {formatTimestamp(event.ts)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {event.sensor_id}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {event.src_ip}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {event.dst_port}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {event.proto}
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={event.severity} />
                    </TableCell>
                    <TableCell className="text-xs">
                      <EventTypeTooltip eventType={event.event_type} />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        )}
      </ScrollArea>

      {/* Footer Info */}
      {data && (
        <div className="text-xs text-muted-foreground">
          Showing {data.events.length} event{data.events.length !== 1 ? 's' : ''} · 
          Refreshes every 5 seconds
        </div>
      )}
    </div>
  );
}
