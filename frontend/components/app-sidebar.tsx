"use client"

import * as React from "react"
import {
  Activity,
  BookText,
  Bot,
  BrainCircuit,
  LayoutDashboard,
  Power,
  Settings,
  Shield,
  ShieldCheck,
  Users,
} from "lucide-react"

import { NavMain } from "@/components/nav-main"
import { NavUser } from "@/components/nav-user"
import { TeamSwitcher } from "@/components/team-switcher"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarRail,
} from "@/components/ui/sidebar"

// Project Guardian data structure
const data = {
  user: {
    name: "Security Admin",
    email: "admin@projectguardian.local",
    avatar: "/avatars/admin.jpg",
  },
  teams: [
    {
      name: "Project Guardian",
      logo: ShieldCheck,
      plan: "Security Monitor",
    },
  ],
  navMain: [
    {
      title: "Dashboard",
      url: "/",
      icon: LayoutDashboard,
      isActive: true,
      items: [
        {
          title: "Übersicht",
          url: "/dashboard/uebersicht",
        },
        {
          title: "Statistiken",
          url: "/stats",
        },
      ],
    },
    {
      title: "Live-Analyse",
      url: "#",
      icon: Activity,
      items: [
        {
          title: "Echtzeit-Monitor",
          url: "/live-monitor",
        },
        {
          title: "Angriffs-Explorer",
          url: "/attack-explorer",
        },
        {
          title: "Geo-Mapping",
          url: "/geo-map",
        },
      ],
    },
    {
      title: "Threat Intelligence",
      url: "#",
      icon: Shield,
      items: [
        {
          title: "Angreifer-Profile",
          url: "/attacker-profiles",
        },
        {
          title: "IP-Analyse",
          url: "/ip-analysis",
        },
        {
          title: "Mustererkennung",
          url: "/pattern-detection",
        },
        {
          title: "Kampagnen-Tracking",
          url: "/campaign-tracking",
        },
      ],
    },
    {
      title: "Täuschungs-Steuerung",
      url: "#",
      icon: Bot,
      items: [
        {
          title: "Desinformations-Logs",
          url: "/deception-logs",
        },
        {
          title: "KI-Prompts & Config",
          url: "/ai-configuration",
        },
        {
          title: "Strategie-Management",
          url: "/strategy-management",
        },
      ],
    },
    {
      title: "System",
      url: "#",
      icon: Settings,
      items: [
        {
          title: "Einstellungen",
          url: "/settings",
        },
        {
          title: "Honeypot-Status",
          url: "/honeypot-status",
        },
        {
          title: "System-Status",
          url: "/system-status",
        },
        {
          title: "API-Keys",
          url: "/api-keys",
        },
      ],
    },
  ],
}

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <TeamSwitcher teams={data.teams} />
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={data.navMain} />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={data.user} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}

