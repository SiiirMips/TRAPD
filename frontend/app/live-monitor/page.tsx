"use client"

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
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  Globe, 
  Users, 
  Server,
  RefreshCw,
  Eye,
  MapPin,
  Clock,
  Zap
} from "lucide-react"
import { useState, useEffect } from "react"

export default function Page() {
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdate, setLastUpdate] = useState(new Date())
  const [threatData, setThreatData] = useState({
    activeThreats: 0,
    blockedAttempts: 0,
    honeypotStatus: "connecting",
    connectedAttackers: 0
  })
  const [recentAttacks, setRecentAttacks] = useState([])
  const [topCountries, setTopCountries] = useState([])
  const [networkActivity, setNetworkActivity] = useState([])
  const [isConnected, setIsConnected] = useState(false)

  // Simulate real-time data updates
  useEffect(() => {
    const connectToWebSocket = () => {
      console.log("Connecting to honeypot data stream...")
      setIsConnected(true)
      
      // Initial data load
      setThreatData({
        activeThreats: Math.floor(Math.random() * 50) + 10,
        blockedAttempts: Math.floor(Math.random() * 2000) + 500,
        honeypotStatus: "active",
        connectedAttackers: Math.floor(Math.random() * 15) + 3
      })

      // Load initial attacks
      const initialAttacks = generateRandomAttacks(10)
      setRecentAttacks(initialAttacks)

      // Load country data
      setTopCountries([
        { country: "Russia", attacks: Math.floor(Math.random() * 100) + 50, percentage: 35 },
        { country: "China", attacks: Math.floor(Math.random() * 80) + 40, percentage: 24 },
        { country: "USA", attacks: Math.floor(Math.random() * 60) + 30, percentage: 16 },
        { country: "Brazil", attacks: Math.floor(Math.random() * 40) + 20, percentage: 10 },
        { country: "India", attacks: Math.floor(Math.random() * 30) + 15, percentage: 8 },
      ])
    }

    connectToWebSocket()

    // Simulate real-time updates every 3-8 seconds
    const updateInterval = setInterval(() => {
      // Update threat metrics
      setThreatData(prev => ({
        activeThreats: Math.max(0, prev.activeThreats + Math.floor(Math.random() * 6) - 2),
        blockedAttempts: prev.blockedAttempts + Math.floor(Math.random() * 10) + 1,
        honeypotStatus: "active",
        connectedAttackers: Math.max(0, prev.connectedAttackers + Math.floor(Math.random() * 4) - 1)
      }))

      // Add new attack (30% chance)
      if (Math.random() < 0.3) {
        const newAttack = generateRandomAttacks(1)[0]
        setRecentAttacks(prev => [newAttack, ...prev.slice(0, 9)])
      }

      // Update country stats
      setTopCountries(prev => prev.map(country => ({
        ...country,
        attacks: country.attacks + Math.floor(Math.random() * 3)
      })))

      setLastUpdate(new Date())
    }, Math.random() * 5000 + 3000) // 3-8 seconds

    // Cleanup
    return () => {
      clearInterval(updateInterval)
      setIsConnected(false)
    }
  }, [])

  const generateRandomAttacks = (count) => {
    const attackTypes = [
      "SSH Brute Force", "Port Scan", "Web Crawling", "SQL Injection", 
      "RDP Attack", "FTP Brute Force", "HTTP Flood", "DNS Tunneling",
      "Malware Download", "Credential Stuffing", "Directory Traversal"
    ]
    const countries = ["RU", "CN", "US", "BR", "IN", "KR", "VN", "TR", "IR", "PL"]
    const severities = ["high", "medium", "low"]
    
    return Array.from({ length: count }, (_, index) => ({
      id: Date.now() + index,
      ip: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
      country: countries[Math.floor(Math.random() * countries.length)],
      type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
      time: "Just now",
      severity: severities[Math.floor(Math.random() * severities.length)],
      port: Math.floor(Math.random() * 65535) + 1,
      userAgent: Math.random() > 0.5 ? "curl/7.68.0" : "Mozilla/5.0...",
      payload: Math.random() > 0.7 ? "Detected" : "None"
    }))
  }

  const handleRefresh = async () => {
    setIsRefreshing(true)
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1500))
    
    // Refresh all data
    setThreatData(prev => ({
      ...prev,
      activeThreats: Math.floor(Math.random() * 50) + 10,
      blockedAttempts: prev.blockedAttempts + Math.floor(Math.random() * 20) + 5
    }))
    
    const newAttacks = generateRandomAttacks(5)
    setRecentAttacks(prev => [...newAttacks, ...prev.slice(0, 5)])
    
    setIsRefreshing(false)
    setLastUpdate(new Date())
  }

  // Auto-update attack times
  useEffect(() => {
    const timeUpdateInterval = setInterval(() => {
      setRecentAttacks(prev => prev.map((attack, index) => ({
        ...attack,
        time: index === 0 ? "Just now" : 
              index < 3 ? `${index + 1} min ago` : 
              `${Math.floor((index + 1) * 2.5)} min ago`
      })))
    }, 60000) // Update every minute

    return () => clearInterval(timeUpdateInterval)
  }, [])

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-12">
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
                    Security Dashboard
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem>
                  <BreadcrumbPage>Live Monitor</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
          <div className="ml-auto flex items-center gap-2 px-4">
            <Badge variant="outline" className={isConnected ? "text-green-600" : "text-orange-600"}>
              <Activity className={`w-3 h-3 mr-1 ${isConnected ? 'animate-pulse' : ''}`} />
              {isConnected ? 'Live' : 'Connecting...'}
            </Badge>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={handleRefresh}
              disabled={isRefreshing}
            >
              <RefreshCw className={`w-4 h-4 mr-1 ${isRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </header>

        <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
          {/* Status Alert */}
          <Alert className={isConnected ? "border-green-200 bg-green-50" : "border-orange-200 bg-orange-50"}>
            <Shield className={`h-4 w-4 ${isConnected ? 'text-green-600' : 'text-orange-600'}`} />
            <AlertDescription className={isConnected ? "text-green-800" : "text-orange-800"}>
              {isConnected 
                ? `All honeypot services are operational. Last updated: ${lastUpdate.toLocaleTimeString()}`
                : "Establishing connection to honeypot network..."
              }
            </AlertDescription>
          </Alert>

          {/* Key Metrics Cards */}
          <div className="grid auto-rows-min gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600 font-mono">{threatData.activeThreats}</div>
                <p className="text-xs text-muted-foreground">
                  {threatData.activeThreats > 20 ? '+High activity' : '+Normal activity'}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Blocked Attempts</CardTitle>
                <Shield className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600 font-mono">{threatData.blockedAttempts.toLocaleString()}</div>
                <p className="text-xs text-muted-foreground">+{Math.floor(Math.random() * 50) + 10} in last hour</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Connected Attackers</CardTitle>
                <Users className="h-4 w-4 text-orange-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-600 font-mono">{threatData.connectedAttackers}</div>
                <p className="text-xs text-muted-foreground">Currently active sessions</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Honeypot Status</CardTitle>
                <Server className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-blue-600 capitalize">{threatData.honeypotStatus}</div>
                <p className="text-xs text-muted-foreground">
                  {isConnected ? '12 services running' : 'Connecting...'}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Main Dashboard Content */}
          <div className="grid gap-4 md:grid-cols-3">
            {/* Real-time Activity Feed */}
            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Real-time Attack Feed
                  <Badge variant="secondary" className="ml-2">
                    {recentAttacks.length} events
                  </Badge>
                </CardTitle>
                <CardDescription>Live monitoring of incoming threats</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  <div className="space-y-3">
                    {recentAttacks.length > 0 ? recentAttacks.map((attack) => (
                      <div key={attack.id} className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors">
                        <div className="flex items-center gap-3">
                          <Badge 
                            variant={attack.severity === 'high' ? 'destructive' : attack.severity === 'medium' ? 'default' : 'secondary'}
                          >
                            {attack.severity}
                          </Badge>
                          <div>
                            <p className="font-medium">{attack.type}</p>
                            <p className="text-sm text-muted-foreground font-mono">
                              {attack.ip}:{attack.port} • {attack.country}
                            </p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-muted-foreground flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {attack.time}
                          </p>
                          <Button variant="outline" size="sm" className="mt-1">
                            <Eye className="h-3 w-3 mr-1" />
                            Details
                          </Button>
                        </div>
                      </div>
                    )) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <Zap className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p>Waiting for attack data...</p>
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            {/* Geographic Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Attack Origins
                </CardTitle>
                <CardDescription>Top attacking countries (last 24h)</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {topCountries.map((country, index) => (
                    <div key={index} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <MapPin className="h-4 w-4" />
                          <span className="font-medium">{country.country}</span>
                        </div>
                        <span className="text-sm text-muted-foreground font-mono">{country.attacks}</span>
                      </div>
                      <Progress value={country.percentage} className="h-2" />
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Analytics Tabs */}
          <Card>
            <CardContent className="p-6">
              <Tabs defaultValue="network" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="network">Network Activity</TabsTrigger>
                  <TabsTrigger value="protocols">Protocols</TabsTrigger>
                  <TabsTrigger value="payloads">Payloads</TabsTrigger>
                  <TabsTrigger value="timeline">Timeline</TabsTrigger>
                </TabsList>
                
                <TabsContent value="network" className="mt-4">
                  <div className="space-y-4">
                    <div className="grid grid-cols-3 gap-4">
                      <div className="text-center p-4 border rounded">
                        <p className="text-2xl font-bold">{Math.floor(Math.random() * 1000) + 500}</p>
                        <p className="text-sm text-muted-foreground">TCP Connections</p>
                      </div>
                      <div className="text-center p-4 border rounded">
                        <p className="text-2xl font-bold">{Math.floor(Math.random() * 200) + 50}</p>
                        <p className="text-sm text-muted-foreground">UDP Packets</p>
                      </div>
                      <div className="text-center p-4 border rounded">
                        <p className="text-2xl font-bold">{Math.floor(Math.random() * 50) + 10}</p>
                        <p className="text-sm text-muted-foreground">Unique IPs</p>
                      </div>
                    </div>
                    <div className="h-[200px] flex items-center justify-center border-2 border-dashed rounded-lg">
                      <p className="text-muted-foreground">Real-time network chart integration ready</p>
                    </div>
                  </div>
                </TabsContent>
                
                <TabsContent value="protocols" className="mt-4">
                  <div className="space-y-3">
                    {['SSH (22)', 'HTTP (80)', 'HTTPS (443)', 'FTP (21)', 'Telnet (23)'].map((protocol, index) => (
                      <div key={protocol} className="flex justify-between items-center p-3 border rounded">
                        <span className="font-medium">{protocol}</span>
                        <div className="flex items-center gap-2">
                          <Progress value={Math.random() * 100} className="w-24 h-2" />
                          <span className="text-sm text-muted-foreground font-mono">
                            {Math.floor(Math.random() * 200) + 10}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>
                
                <TabsContent value="payloads" className="mt-4">
                  <div className="space-y-3">
                    <Alert>
                      <AlertTriangle className="h-4 w-4" />
                      <AlertDescription>
                        {Math.floor(Math.random() * 15) + 5} malicious payloads detected in the last hour
                      </AlertDescription>
                    </Alert>
                    <div className="h-[200px] flex items-center justify-center border-2 border-dashed rounded-lg">
                      <p className="text-muted-foreground">Payload analysis visualization ready</p>
                    </div>
                  </div>
                </TabsContent>
                
                <TabsContent value="timeline" className="mt-4">
                  <div className="space-y-3">
                    {Array.from({ length: 5 }, (_, i) => (
                      <div key={i} className="flex items-center gap-4 p-3 border rounded">
                        <div className="text-sm text-muted-foreground font-mono">
                          {new Date(Date.now() - i * 300000).toLocaleTimeString()}
                        </div>
                        <Badge variant="outline">
                          {Math.floor(Math.random() * 20) + 5} events
                        </Badge>
                        <div className="flex-1">
                          <Progress value={Math.random() * 100} className="h-2" />
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
