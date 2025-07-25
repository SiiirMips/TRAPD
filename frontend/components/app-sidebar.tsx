"use client"

import * as React from "react"
import Image from "next/image"
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
        <div className="flex items-center justify-center px-2 py-3 group-data-[collapsible=icon]:px-2">
          <div className="flex h-8 w-8 items-center justify-center group-data-[collapsible=icon]:h-8 group-data-[collapsible=icon]:w-8">
            {/* Inline SVG Logo */}
            <svg 
              width="32" 
              height="32" 
              viewBox="0 0 200 200" 
              xmlns="http://www.w3.org/2000/svg"
              className="h-8 w-8 group-data-[collapsible=icon]:h-6 group-data-[collapsible=icon]:w-6"
            >
              <polygon points="100,60 140,100 100,140 60,100" fill="currentColor" className="text-foreground"/>
              <polygon points="100,85 115,100 100,115 85,100" fill="currentColor" className="text-background"/>
            </svg>
          </div>
          <div className="ml-3 grid flex-1 text-left leading-tight group-data-[collapsible=icon]:hidden">
            <span className="truncate font-bold text-2xl text-foreground tracking-tight">TRAPD</span>
            <span className="truncate text-sm text-muted-foreground font-medium">Cybersecurity Solutions</span>
          </div>
        </div>
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

