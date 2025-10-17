"use client"
import React, { createContext, useContext, useEffect, useState } from "react"

type SidebarFavoritesContextType = {
  favorites: string[]
  toggleFavorite: (url: string) => void
}

const SidebarFavoritesContext = createContext<SidebarFavoritesContextType | undefined>(undefined)

export function SidebarFavoritesProvider({ children }: { children: React.ReactNode }) {
  const [favorites, setFavorites] = useState<string[]>([])
  useEffect(() => {
    if (typeof window === "undefined") return
    const stored = localStorage.getItem("sidebar-favorites")
    if (stored) setFavorites(JSON.parse(stored))
  }, [])
  useEffect(() => {
    if (typeof window === "undefined") return
    localStorage.setItem("sidebar-favorites", JSON.stringify(favorites))
  }, [favorites])
  const toggleFavorite = (url: string) => {
    setFavorites((prev) =>
      prev.includes(url) ? prev.filter((u) => u !== url) : [...prev, url]
    )
  }
  return (
    <SidebarFavoritesContext.Provider value={{ favorites, toggleFavorite }}>
      {children}
    </SidebarFavoritesContext.Provider>
  )
}

export function useSidebarFavoritesCtx() {
  const ctx = useContext(SidebarFavoritesContext)
  if (!ctx) throw new Error("useSidebarFavoritesCtx must be used within SidebarFavoritesProvider")
  return ctx
}
