import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono, Newsreader } from "next/font/google";
import "./globals.css";

const sans = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });
const serif = Newsreader({ subsets: ["latin"], style: ["italic", "normal"], variable: "--font-serif", display: "swap" });

export const metadata: Metadata = {
  title: "IntentGuard: the check between your AI agent and your data",
  description:
    "A research prototype that checks every tool call an AI agent makes against what the person actually asked for, before it runs. Replay real decisions, tamper with the audit log, and try to smuggle a secret past it.",
};

export const viewport: Viewport = { themeColor: "#05070b", width: "device-width", initialScale: 1 };

// Runs before first paint so a saved theme does not flash.
const themeInit = `try{var t=localStorage.getItem("ig-theme");if(t)document.documentElement.setAttribute("data-theme",t)}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable} ${serif.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInit }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
