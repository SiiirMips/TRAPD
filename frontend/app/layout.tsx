import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "Project Guardian - Honeypot Dashboard",
  description:
    "Advanced honeypot monitoring and threat detection dashboard for cybersecurity professionals",
  keywords: [
    "honeypot",
    "cybersecurity",
    "threat detection",
    "monitoring",
    "security",
  ],
  authors: [{ name: "Project Guardian Team" }],
  viewport: "width=device-width, initial-scale=1",
  robots: "noindex, nofollow", // Security dashboard shouldn't be indexed
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="de" className="scroll-smooth">
      <head>
        <link rel="icon" href="/favicon.ico" />
        <meta name="theme-color" content="#1e40af" />
      </head>
      <body
        className={`${inter.variable} font-sans antialiased bg-gradient-to-br from-slate-50 to-slate-100 min-h-screen`}
      >
        <div className="relative">
          {/* Background Pattern */}
          <div className="fixed inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(59,130,246,0.05),transparent_50%)] pointer-events-none" />

          {/* Main Content */}
          <main className="relative z-10">{children}</main>

          {/* Footer */}
          <footer className="relative z-10 mt-16 border-t border-slate-200 bg-white/80 backdrop-blur-sm">
            <div className="container mx-auto max-w-7xl px-4 py-6">
              <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-gradient-to-r from-blue-600 to-indigo-600 rounded"></div>
                  <span className="text-sm text-slate-600 font-medium">
                    Project Guardian © 2024
                  </span>
                </div>
                <div className="flex items-center gap-6 text-xs text-slate-500">
                  <span>Honeypot Monitoring System</span>
                  <span>•</span>
                  <span>Threat Detection Dashboard</span>
                </div>
              </div>
            </div>
          </footer>
        </div>
      </body>
    </html>
  );
}
