'use client';

import * as React from "react";
import { AppSidebar } from "@/components/app-sidebar"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
import { Separator } from "@/components/ui/separator"
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { OverviewCards } from '@/components/overview-cards';
import { Trends } from '@/components/trends';
import { TopOffenders } from '@/components/top-offenders';
import { HealthSensors } from '@/components/health-sensors';
import { LiveFeedFilters } from '@/components/live-feed-filters';
import { LiveFeed } from '@/components/live-feed';


export default function Page() {
  // Filter-State für LiveFeedFilters
  const [ipPort, setIpPort] = React.useState('');
  const [severity, setSeverity] = React.useState('');
  const [sensorId, setSensorId] = React.useState('');
  const handleReset = () => {
    setIpPort('');
    setSeverity('');
    setSensorId('');
  };

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2">
          <div className="flex items-center gap-2 px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator
              orientation="vertical"
              className="mr-2 data-[orientation=vertical]:h-4"
            />
            <Breadcrumb>
              <BreadcrumbList>
                <BreadcrumbItem className="hidden md:block">
                  <BreadcrumbLink href="/dashboard">
                    Dashboard
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem>
                  <BreadcrumbPage>Overview</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </header>
        <div className="flex flex-1 flex-col gap-8 p-6">
          {/* Overview Cards (oben, erweitert) */}
          <OverviewCards />

          {/* Grid mit Trends, TopOffenders, HealthSensors */}
          <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
            <Trends />
            <TopOffenders />
            <HealthSensors />
          </div>

          {/* Filterleiste in Card */}
          <LiveFeedFilters
            ipPort={ipPort}
            setIpPort={setIpPort}
            severity={severity}
            setSeverity={setSeverity}
            sensorId={sensorId}
            setSensorId={setSensorId}
            onReset={handleReset}
          />

          {/* Live Feed */}
          <LiveFeed
            ipPort={ipPort}
            severity={severity}
            sensorId={sensorId}
          />
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
