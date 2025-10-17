import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Input } from '@/components/ui/input';
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from '@/components/ui/select';
import { Button } from '@/components/ui/button';

export function LiveFeedFilters({ ipPort, setIpPort, severity, setSeverity, sensorId, setSensorId, onReset }: any) {
  return (
    <Card className="mb-4">
      <CardContent>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1 space-y-1.5">
            <label className="text-sm font-medium">IP / Port</label>
            <Input placeholder="Filter by IP or Port..." value={ipPort} onChange={e => setIpPort(e.target.value)} />
          </div>
          <div className="w-full sm:w-[180px] space-y-1.5">
            <label className="text-sm font-medium">Severity</label>
            <Select value={severity} onValueChange={val => setSeverity(val === 'all' ? '' : val)}>
              <SelectTrigger><SelectValue placeholder="All Severities" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="LOW">LOW</SelectItem>
                <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                <SelectItem value="HIGH">HIGH</SelectItem>
                <SelectItem value="CRITICAL">CRITICAL</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="w-full sm:w-[180px] space-y-1.5">
            <label className="text-sm font-medium">Sensor</label>
            <Select value={sensorId} onValueChange={val => setSensorId(val === 'all' ? '' : val)}>
              <SelectTrigger><SelectValue placeholder="All Sensors" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sensors</SelectItem>
                {Array.from({ length: 10 }, (_, i) => (
                  <SelectItem key={i + 1} value={`sensor-${i + 1}`}>sensor-{i + 1}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button variant="outline" onClick={onReset}>Reset</Button>
        </div>
        <Separator className="my-4" />
        <div className="text-xs text-muted-foreground">Auto-Refresh alle 5 Sekunden</div>
      </CardContent>
    </Card>
  );
}
