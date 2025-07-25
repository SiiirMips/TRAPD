import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";

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
    <html lang="de" className="scroll-smooth" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/favicon.ico" />
        <meta name="theme-color" content="#1e40af" />
        <meta name="color-scheme" content="dark light" />
      </head>
      <body
        className={`${inter.variable} font-sans antialiased bg-background text-foreground min-h-screen transition-colors duration-300`}
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          storageKey="project-guardian-theme"
        >
          <div className="relative">
            {/* Background Pattern with adaptive colors */}
            <div className="fixed inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(213,189,175,0.1),transparent_50%)] dark:bg-[radial-gradient(circle_at_50%_50%,rgba(59,130,246,0.05),transparent_50%)] pointer-events-none transition-all duration-300" />

            {/* Main Content */}
            <main className="relative z-10">{children}</main>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
