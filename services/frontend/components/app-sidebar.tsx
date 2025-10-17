"use client"

import * as React from "react"
import {
  Activity,
  BarChart3,
  BookOpen,
  Crosshair,
  HardDrive,
  LayoutDashboard,
  LifeBuoy,
  Settings,
  ShieldAlert,
  Target,
  Terminal,
  Webhook,
} from "lucide-react"
import { Inter } from "next/font/google"

import { NavMain } from "@/components/nav-main"
import { NavProjects } from "@/components/nav-projects"
import { NavSecondary } from "@/components/nav-secondary"
import { NavUser } from "@/components/nav-user"
import { useSession } from "next-auth/react"
import { SidebarFavoritesProvider, useSidebarFavoritesCtx } from "@/components/sidebar-favorites-context"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
} from "@/components/ui/sidebar"

const inter = Inter({ 
  subsets: ["latin"], 
  weight: ["600", "700"],
  variable: "--font-inter"
})

const data = {
  user: {
    name: "SOC Analyst",
    email: "analyst@trapd.sec",
    avatar: "/avatars/analyst.jpg",
  },
  navMain: [
    // ...existing code...
    // (alle Hauptnavigationseinträge wie oben)
    {
      title: "Dashboard",
      url: "/",
      icon: LayoutDashboard,
      isActive: true,
    },
    {
      title: "Live-Lage",
      url: "/live",
      icon: Activity,
      items: [
        { title: "Events Stream", url: "/live/events" },
        { title: "Alerts", url: "/live/alerts" },
        { title: "Sessions", url: "/live/sessions" },
        { title: "Geo-Map", url: "/live/map" },
      ],
    },
    {
      title: "Detection & Intel",
      url: "/detections",
      icon: Crosshair,
      items: [
        { title: "Regeln & Signaturen", url: "/detections/rules" },
        { title: "IOC-Feeds", url: "/detections/iocs" },
        { title: "TTPs (ATT&CK)", url: "/detections/ttps" },
        { title: "Threat Intel", url: "/intel/reputation" },
        { title: "Malware-Familien", url: "/intel/malware" },
        { title: "Kampagnen", url: "/intel/campaigns" },
      ],
    },
    {
      title: "Honeypots",
      url: "/sensors",
      icon: Target,
      items: [
        { title: "Knotenübersicht", url: "/sensors/nodes" },
        { title: "Services/Emulationen", url: "/sensors/services" },
        { title: "Tarnobjekte (Baits)", url: "/sensors/baits" },
        { title: "Netzwerk-Täuschung", url: "/deception/network" },
      ],
    },
    {
      title: "Response & Forensik",
      url: "/cases",
      icon: ShieldAlert,
      items: [
        { title: "Offene Fälle", url: "/cases/open" },
        { title: "SLA-Übersicht", url: "/cases/sla" },
        { title: "Playbooks", url: "/response/playbooks" },
        { title: "Containment-Aktionen", url: "/response/actions" },
        { title: "PCAPs", url: "/forensics/pcaps" },
        { title: "Artefakte", url: "/forensics/artifacts" },
        { title: "Timeline", url: "/forensics/timeline" },
      ],
    },
    {
      title: "Analytics",
      url: "/analytics",
      icon: BarChart3,
      items: [
        { title: "Trends", url: "/analytics/trends" },
        { title: "Heatmaps", url: "/analytics/heatmaps" },
        { title: "Angriffspfade", url: "/analytics/paths" },
        { title: "Reports", url: "/reports/executive" },
      ],
    },
    {
      title: "Administration",
      url: "/settings",
      icon: Settings,
      items: [
        { title: "Rollen & RBAC", url: "/settings/roles" },
        { title: "API-Keys", url: "/settings/api-keys" },
        { title: "Datenhaltung", url: "/settings/retention" },
        { title: "System-Status", url: "/system/health" },
        { title: "Queues & Worker", url: "/system/queues" },
      ],
    },
  ],
  navSecondary: [
    { title: "Dokumentation", url: "/help/docs", icon: BookOpen },
    { title: "Support", url: "/help/support", icon: LifeBuoy },
  ],
}


function SidebarFavoritesProjects({ navMain }: { navMain: typeof data.navMain }) {
  const { favorites } = useSidebarFavoritesCtx()
  const favoriteItems: { name: string; url: string; icon: any }[] = []
  for (const main of navMain) {
    if (!main.items) continue
    for (const sub of main.items) {
      if (favorites.includes(sub.url)) {
        favoriteItems.push({ name: sub.title, url: sub.url, icon: main.icon })
      }
    }
  }
  if (favoriteItems.length === 0) return null
  return <NavProjects projects={favoriteItems} />
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const { data: session } = useSession()
  const userName = session?.user?.name || data.user.name
  const userEmail = session?.user?.email || data.user.email
  const userAvatar = data.user.avatar
  return (
    <SidebarFavoritesProvider>
      <Sidebar variant="inset" {...props}>
        <SidebarHeader className="h-16 border-b border-border/60">
          <a 
            href="/" 
            className="flex items-center h-full px-4"
          >
            <span className={`${inter.className} text-xl font-semibold tracking-wide text-foreground`}>
              TRAPD
            </span>
          </a>
        </SidebarHeader>
        <SidebarContent>
          <NavMain items={data.navMain} />
          <SidebarFavoritesProjects navMain={data.navMain} />
          <NavSecondary items={data.navSecondary} className="mt-auto" />
        </SidebarContent>
        <SidebarFooter>
          <NavUser user={{ name: userName, email: userEmail, avatar: userAvatar }} />
        </SidebarFooter>
      </Sidebar>
    </SidebarFavoritesProvider>
  )
}
