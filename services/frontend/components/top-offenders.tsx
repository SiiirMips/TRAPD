import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Sheet, SheetTrigger, SheetContent } from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { useApi } from '@/hooks/useApi';
import { useState } from 'react';
import { Bar } from 'react-chartjs-2';

export function TopOffenders() {
  const { data, isLoading, error } = useApi('/api/offenders/top');
  const [selectedIp, setSelectedIp] = useState<string | null>(null);

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle>Top Offender IPs (24h)</CardTitle></CardHeader>
        <CardContent><Skeleton className="h-40 w-full" /></CardContent>
      </Card>
    );
  }
  if (error || !data || !data.offenders) {
    return (
      <Card>
        <CardHeader><CardTitle>Top Offender IPs (24h)</CardTitle></CardHeader>
        <CardContent className="text-muted-foreground">Keine Daten vorhanden</CardContent>
      </Card>
    );
  }

  // Chart für Top Offender IPs
  const chartData = {
    labels: data.offenders.map((o: any) => o.src_ip),
    datasets: [
      {
        label: 'Count',
        data: data.offenders.map((o: any) => o.count),
        backgroundColor: '#888',
        borderRadius: 4,
      },
    ],
  };

  return (
    <Card>
      <CardHeader><CardTitle>Top Offender IPs (24h)</CardTitle></CardHeader>
      <CardContent>
        <div className="w-full h-40 mb-4">
          <Bar
            data={chartData}
            options={{
              indexAxis: 'y',
              plugins: { legend: { display: false } },
              scales: {
                x: { grid: { color: '#eee' }, ticks: { color: '#888', font: { size: 10 } } },
                y: { grid: { display: false }, ticks: { color: '#888', font: { size: 10 } } },
              },
              responsive: true,
              maintainAspectRatio: false,
            }}
          />
        </div>
        <ScrollArea className="h-[32vh]">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source IP</TableHead>
                <TableHead>Count</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead>Top Port</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.offenders.map((off: any) => (
                <TableRow key={off.src_ip} className="cursor-pointer" onClick={() => setSelectedIp(off.src_ip)}>
                  <TableCell className="font-mono text-xs">{off.src_ip}</TableCell>
                  <TableCell>{off.count}</TableCell>
                  <TableCell>{off.last_seen}</TableCell>
                  <TableCell>{off.top_port}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </ScrollArea>
        <Sheet open={!!selectedIp} onOpenChange={() => setSelectedIp(null)}>
          <SheetContent side="right" className="w-[480px]">
            <div className="flex flex-col gap-4">
              <div className="flex justify-between items-center">
                <span className="font-semibold">Events für {selectedIp}</span>
                <Button variant="outline">Export</Button>
              </div>
              <ScrollArea className="h-[60vh]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Sensor</TableHead>
                      <TableHead>Port</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Event Type</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {/* Hier: Events für die IP aus /api/events?src_ip=... */}
                  </TableBody>
                </Table>
              </ScrollArea>
            </div>
          </SheetContent>
        </Sheet>
      </CardContent>
    </Card>
  );
}
