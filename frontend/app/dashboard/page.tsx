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
import { 
  Activity, 
  Shield, 
  AlertTriangle, 
  Users, 
  Scan, 
  Eye, 
  Globe, 
  Clock,
  TrendingUp,
  Bot,
  Monitor,
  Fingerprint
} from "lucide-react"

export default function Page() {
  // Mock data - in real app würde das von Supabase kommen
  const mockData = {
    totalAttacks: 1247,
    uniqueIPs: 89,
    threatsBlocked: 234,
    scannersDetected: 45,
    realTimeThreat: "HIGH",
    topScanners: [
      { name: "Nmap", count: 89, confidence: 0.95 },
      { name: "Masscan", count: 67, confidence: 0.92 },
      { name: "Gobuster", count: 45, confidence: 0.88 },
      { name: "Nikto", count: 32, confidence: 0.85 }
    ],
    threatLevels: {
      critical: 12,
      high: 34,
      medium: 67,
      low: 89
    },
    browserFingerprints: 156,
    countries: [
      { name: "Russia", count: 234, flag: "🇷🇺" },
      { name: "China", count: 189, flag: "🇨🇳" },
      { name: "USA", count: 156, flag: "🇺🇸" },
      { name: "Germany", count: 67, flag: "🇩🇪" }
    ]
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case "CRITICAL": return "bg-red-500"
      case "HIGH": return "bg-orange-500"
      case "MEDIUM": return "bg-yellow-500"
      case "LOW": return "bg-green-500"
      default: return "bg-gray-500"
    }
  }

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
                    🍯 Honeypot Guardian
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem>
                  <BreadcrumbPage>Advanced Fingerprinting Dashboard</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>
        </header>
        
        <div className="flex flex-1 flex-col gap-6 p-6 pt-0">
          {/* Real-time Status Bar */}
          <div className="flex items-center justify-between p-4 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg text-white">
            <div className="flex items-center gap-3">
              <Shield className="h-6 w-6" />
              <div>
                <h2 className="text-lg font-semibold">🔍 Advanced Fingerprinting System</h2>
                <p className="text-sm opacity-90">Real-time Scanner Detection & Browser Fingerprinting</p>
              </div>
            </div>
            <Badge className={`${getThreatColor(mockData.realTimeThreat)} text-white px-3 py-1`}>
              THREAT LEVEL: {mockData.realTimeThreat}
            </Badge>
          </div>

          {/* Key Metrics Grid */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card className="border-l-4 border-l-blue-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Attacks</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{mockData.totalAttacks.toLocaleString()}</div>
                <p className="text-xs text-muted-foreground">
                  <TrendingUp className="inline h-3 w-3 mr-1" />
                  +12.5% from last hour
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-green-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Unique IPs</CardTitle>
                <Users className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{mockData.uniqueIPs}</div>
                <p className="text-xs text-muted-foreground">
                  <Globe className="inline h-3 w-3 mr-1" />
                  From 23 countries
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-orange-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Scanners Detected</CardTitle>
                <Scan className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{mockData.scannersDetected}</div>
                <p className="text-xs text-muted-foreground">
                  <Bot className="inline h-3 w-3 mr-1" />
                  Nmap, Masscan, Gobuster
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-purple-500">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Browser Fingerprints</CardTitle>
                <Fingerprint className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{mockData.browserFingerprints}</div>
                <p className="text-xs text-muted-foreground">
                  <Monitor className="inline h-3 w-3 mr-1" />
                  Canvas, WebGL, Audio
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Analytics Grid */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            
            {/* Scanner Detection Card */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Scan className="h-5 w-5" />
                  🔍 Scanner Detection Results
                </CardTitle>
                <CardDescription>
                  Real-time detection of scanning tools with confidence scores
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {mockData.topScanners.map((scanner, index) => (
                  <div key={scanner.name} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                    <div className="flex items-center gap-3">
                      <Badge variant="outline">#{index + 1}</Badge>
                      <div>
                        <p className="font-medium">{scanner.name}</p>
                        <p className="text-sm text-muted-foreground">{scanner.count} detections</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-medium">{(scanner.confidence * 100).toFixed(1)}%</p>
                      <Progress value={scanner.confidence * 100} className="w-20" />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Threat Level Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5" />
                  🚨 Threat Levels
                </CardTitle>
                <CardDescription>
                  Distribution of threat assessments
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                    Critical
                  </span>
                  <Badge variant="destructive">{mockData.threatLevels.critical}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                    High
                  </span>
                  <Badge variant="secondary">{mockData.threatLevels.high}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                    Medium
                  </span>
                  <Badge variant="outline">{mockData.threatLevels.medium}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    Low
                  </span>
                  <Badge variant="outline">{mockData.threatLevels.low}</Badge>
                </div>
              </CardContent>
            </Card>

            {/* Geographic Distribution */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  🌍 Attack Origins
                </CardTitle>
                <CardDescription>
                  Top attacking countries
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {mockData.countries.map((country, index) => (
                  <div key={country.name} className="flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <span className="text-lg">{country.flag}</span>
                      {country.name}
                    </span>
                    <Badge variant="outline">{country.count}</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Browser Fingerprinting Stats */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Fingerprint className="h-5 w-5" />
                  🔍 Browser Fingerprinting
                </CardTitle>
                <CardDescription>
                  JavaScript fingerprinting results
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Canvas Fingerprints</span>
                    <span>142</span>
                  </div>
                  <Progress value={85} />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>WebGL Fingerprints</span>
                    <span>134</span>
                  </div>
                  <Progress value={80} />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Audio Fingerprints</span>
                    <span>89</span>
                  </div>
                  <Progress value={65} />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Real Browsers</span>
                    <span>23</span>
                  </div>
                  <Progress value={15} />
                </div>
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  ⚡ Recent Activity
                </CardTitle>
                <CardDescription>
                  Latest fingerprinting detections
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="text-sm space-y-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="destructive" className="text-xs">NMAP</Badge>
                    <span className="text-muted-foreground">192.168.1.100</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-xs">MASS</Badge>
                    <span className="text-muted-foreground">10.0.0.55</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">GOBU</Badge>
                    <span className="text-muted-foreground">172.16.0.23</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className="text-xs">BRWS</Badge>
                    <span className="text-muted-foreground">203.0.113.45</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Real-time Monitoring Section */}
          <Card className="bg-gradient-to-r from-slate-900 to-slate-800 text-white">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5" />
                🎯 Real-time Fingerprinting Monitor
              </CardTitle>
              <CardDescription className="text-slate-300">
                Live feed of advanced fingerprinting detections
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3 font-mono text-sm">
                <div className="flex items-center gap-3 p-2 rounded bg-black/20">
                  <Badge className="bg-red-500">CRIT</Badge>
                  <span className="text-green-400">13:42:15</span>
                  <span>Nmap NSE Script detected → 192.168.1.100 (RU)</span>
                  <Badge variant="outline" className="ml-auto">95% confidence</Badge>
                </div>
                <div className="flex items-center gap-3 p-2 rounded bg-black/20">
                  <Badge className="bg-orange-500">HIGH</Badge>
                  <span className="text-green-400">13:41:58</span>
                  <span>Masscan burst detected → 10.0.0.55 (CN)</span>
                  <Badge variant="outline" className="ml-auto">92% confidence</Badge>
                </div>
                <div className="flex items-center gap-3 p-2 rounded bg-black/20">
                  <Badge className="bg-blue-500">INFO</Badge>
                  <span className="text-green-400">13:41:42</span>
                  <span>Browser fingerprint collected → 203.0.113.45 (US)</span>
                  <Badge variant="outline" className="ml-auto">Canvas+WebGL</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
