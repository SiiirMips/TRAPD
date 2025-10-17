import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useApi } from '@/hooks/useApi';

export function HealthSensors() {
  const { data, isLoading, error } = useApi('/api/health/sensors');

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle>System Health</CardTitle></CardHeader>
        <CardContent><Skeleton className="h-40 w-full" /></CardContent>
      </Card>
    );
  }
  if (error || !data || !data.sensors) {
    return (
      <Card>
        <CardHeader><CardTitle>System Health</CardTitle></CardHeader>
        <CardContent className="text-muted-foreground">Keine Daten vorhanden</CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader><CardTitle>System Health</CardTitle></CardHeader>
      <CardContent>
        <ScrollArea className="h-[32vh]">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Sensor ID</TableHead>
                <TableHead>Last Seen</TableHead>
                <TableHead>Alive</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.sensors.map((sensor: any) => (
                <TableRow key={sensor.id}>
                  <TableCell>{sensor.id}</TableCell>
                  <TableCell>{sensor.last_seen}</TableCell>
                  <TableCell>
                    <Badge className={sensor.alive ? 'bg-green-500 text-white' : 'bg-gray-300 text-gray-700'}>
                      {sensor.alive ? 'Alive' : 'Stale'}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
