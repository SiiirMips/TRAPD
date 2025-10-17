import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useApi } from '@/hooks/useApi';
import { Line } from 'react-chartjs-2';
import { Chart, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend } from 'chart.js';
Chart.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

export function Trends() {
  const { data, isLoading, error } = useApi('/api/trends/events');

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle>Events pro Stunde</CardTitle></CardHeader>
        <CardContent><Skeleton className="h-40 w-full" /></CardContent>
      </Card>
    );
  }
  if (error || !data || !data.trend) {
    return (
      <Card>
        <CardHeader><CardTitle>Events pro Stunde</CardTitle></CardHeader>
        <CardContent className="text-muted-foreground">Keine Daten vorhanden</CardContent>
      </Card>
    );
  }
  const chartData = {
    labels: data.trend.map((t: any) => t.hour),
    datasets: [{
      label: 'Events',
      data: data.trend.map((t: any) => t.count),
      borderColor: '#888',
      backgroundColor: 'rgba(200,200,200,0.2)',
      tension: 0.3,
      pointRadius: 2,
      pointBackgroundColor: '#888',
    }],
  };
  return (
    <Card>
      <CardHeader><CardTitle>Events pro Stunde</CardTitle></CardHeader>
      <CardContent>
        <div className="w-full h-48">
          <Line
            data={chartData}
            options={{
              plugins: { legend: { display: false } },
              scales: {
                x: { grid: { display: false }, ticks: { color: '#888', font: { size: 10 } } },
                y: { grid: { color: '#eee' }, ticks: { color: '#888', font: { size: 10 } } },
              },
              elements: { line: { borderWidth: 2 } },
              responsive: true,
              maintainAspectRatio: false,
            }}
          />
        </div>
      </CardContent>
    </Card>
  );
}
