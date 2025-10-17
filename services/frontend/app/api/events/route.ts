import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const limit = parseInt(searchParams.get('limit') || '200');
    const ipPort = searchParams.get('ipPort') || '';
    const severity = searchParams.get('severity') || '';
    const sensorId = searchParams.get('sensorId') || '';

    // Mock data for demonstration
    // In production, this would query your database with filters
    const mockEvents = Array.from({ length: limit }, (_, i) => ({
      id: i + 1,
      ts: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      sensor_id: `sensor-${Math.floor(Math.random() * 10) + 1}`,
      src_ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      dst_port: [22, 80, 443, 3306, 5432, 8080][Math.floor(Math.random() * 6)],
      proto: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
      severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)],
      event_type: ['port_scan', 'brute_force', 'dos', 'malware', 'intrusion'][Math.floor(Math.random() * 5)],
    }));

    // Apply filters (mock filtering)
    let filteredEvents = mockEvents;
    
    if (ipPort) {
      filteredEvents = filteredEvents.filter(
        e => e.src_ip.includes(ipPort) || e.dst_port.toString().includes(ipPort)
      );
    }
    
    if (severity) {
      filteredEvents = filteredEvents.filter(e => e.severity === severity);
    }
    
    if (sensorId) {
      filteredEvents = filteredEvents.filter(e => e.sensor_id === sensorId);
    }

    // Sort by timestamp descending (newest first)
    filteredEvents.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

    return NextResponse.json({
      events: filteredEvents,
      total: filteredEvents.length,
    });
  } catch (error) {
    console.error('Error fetching events:', error);
    return NextResponse.json(
      { error: 'Failed to fetch events' },
      { status: 500 }
    );
  }
}
