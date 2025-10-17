"use client"


import { ChevronRight, Star, StarOff, type LucideIcon } from "lucide-react"
import { useSidebarFavoritesCtx } from "@/components/sidebar-favorites-context"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuAction,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar"


type SubItem = {
  title: string
  url: string
}

type MainItem = {
  title: string
  url: string
  icon: LucideIcon
  isActive?: boolean
  items?: SubItem[]
}

// Favoriten-Logik kommt jetzt aus Context
export function NavMain({ items }: { items: MainItem[] }) {
  const { favorites, toggleFavorite } = useSidebarFavoritesCtx()
  return (
    <SidebarGroup>
      <SidebarGroupLabel>Hauptnavigation</SidebarGroupLabel>
      <SidebarMenu>
        {items.map((item) => (
          <Collapsible key={item.title} asChild defaultOpen={item.isActive}>
            <SidebarMenuItem>
              <SidebarMenuButton asChild tooltip={item.title}>
                <a href={item.url}>
                  <item.icon />
                  <span>{item.title}</span>
                </a>
              </SidebarMenuButton>
              {item.items?.length ? (
                <>
                  <CollapsibleTrigger asChild>
                    <SidebarMenuAction className="data-[state=open]:rotate-90">
                      <ChevronRight />
                      <span className="sr-only">Toggle</span>
                    </SidebarMenuAction>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <SidebarMenuSub>
                      {item.items?.map((subItem) => {
                        const isFav = favorites.includes(subItem.url)
                        return (
                          <SidebarMenuSubItem key={subItem.title}>
                            <div className="flex items-center w-full">
                              <SidebarMenuSubButton asChild className="flex-1">
                                <a href={subItem.url}>
                                  <span>{subItem.title}</span>
                                </a>
                              </SidebarMenuSubButton>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <button
                                    type="button"
                                    aria-label={isFav ? "Aus Schnellzugriff entfernen" : "Zum Schnellzugriff hinzufügen"}
                                    className="ml-2 p-1 rounded focus:outline-none focus-visible:ring"
                                    onClick={() => toggleFavorite(subItem.url)}
                                    tabIndex={0}
                                  >
                                    {isFav ? (
                                      <Star className="size-4 text-yellow-400" fill="currentColor" />
                                    ) : (
                                      <Star className="size-4 text-muted-foreground" />
                                    )}
                                  </button>
                                </TooltipTrigger>
                                <TooltipContent side="right">
                                  {isFav ? "Aus Schnellzugriff entfernen" : "Zum Schnellzugriff hinzufügen"}
                                </TooltipContent>
                              </Tooltip>
                            </div>
                          </SidebarMenuSubItem>
                        )
                      })}
                    </SidebarMenuSub>
                  </CollapsibleContent>
                </>
              ) : null}
            </SidebarMenuItem>
          </Collapsible>
        ))}
      </SidebarMenu>
    </SidebarGroup>
  )
}
