import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const window = searchParams.get('window') || '24h';

    // Mock data for demonstration
    // In production, this would query your database
    const stats = {
      events24h: {
        value: '12,847',
        label: 'Events 24h',
      },
      uniqueIps24h: {
        value: '342',
        label: 'Unique IPs 24h',
      },
      topSeverity: {
        value: 'HIGH',
        label: 'Top Severity',
      },
      hotPort: {
        value: '22',
        label: 'Hot Port',
      },
      sensorsAlive: {
        value: '8/10',
        label: 'Sensors Alive',
      },
    };

    return NextResponse.json(stats);
  } catch (error) {
    console.error('Error fetching overview stats:', error);
    return NextResponse.json(
      { error: 'Failed to fetch overview stats' },
      { status: 500 }
    );
  }
}
