import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { useApi } from '@/hooks/useApi';

export function OverviewCards() {
  const { data, isLoading, error } = useApi('/api/stats/overview?window=24h');

  // Mock für neue Cards
  const extended = [
    { label: 'Events (7d)', value: '89,123' },
    { label: 'Critical Events (24h)', value: '42' },
    { label: 'Top Event Type (24h)', value: 'port_scan' },
    { label: 'Sensors Alive', value: '8/10', progress: 80 },
  ];

  if (isLoading) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
        {Array.from({ length: 9 }).map((_, i) => (
          <Card key={i}><CardHeader><Skeleton className="h-4 w-24" /></CardHeader><CardContent><Skeleton className="h-8 w-32" /></CardContent></Card>
        ))}
      </div>
    );
  }

  if (error || !data) {
    return <div className="text-muted-foreground">Fehler beim Laden der Statistiken</div>;
  }

  // Kombiniere alte und neue Cards
  const cards = [
    { label: data.events24h.label, value: data.events24h.value },
    { label: data.uniqueIps24h.label, value: data.uniqueIps24h.value },
    { label: data.topSeverity.label, value: <Badge variant="outline">{data.topSeverity.value}</Badge> },
    { label: data.hotPort.label, value: data.hotPort.value },
    { label: data.sensorsAlive.label, value: data.sensorsAlive.value },
    ...extended,
  ];

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      {cards.map((card, i) => (
        <Card key={i}>
          <CardHeader>
            <CardTitle className="text-sm font-normal text-muted-foreground">{card.label}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col gap-2">
              <div className="text-2xl font-semibold tracking-tight">{card.value}</div>
              {card.progress !== undefined && (
                <Progress value={card.progress} className="h-2" />
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
