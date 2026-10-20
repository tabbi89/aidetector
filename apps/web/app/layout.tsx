import type { Metadata, Viewport } from "next";
import { BrandLink } from "./components/AppHome";
import { Nav } from "./components/Nav";
import { ThemeToggle } from "./components/ThemeToggle";
import { AuthGate } from "./components/AuthGate";
import { FooterLinks } from "./components/FooterLinks";
import { AccountMenu } from "./components/AccountMenu";
import { ConnectionProvider } from "@/lib/connection";
import "./globals.css";
import "./styles/features.css";
import "./styles/settings.css";
import "./styles/results.css";
import "./styles/cli-guide.css";

export const metadata: Metadata = {
  title: {
    default: "aidetector — active API security scanning",
    template: "%s · aidetector",
  },
  description:
    "OpenAPI-driven API security scanner — active OWASP API Top 10 testing with an Opus + DeepSeek adjudication cascade.",
  icons: {
    icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%231a54ff'/><path d='M16 6l8 3.5v6c0 5-3.4 8.9-8 10.5-4.6-1.6-8-5.5-8-10.5v-6L16 6z' fill='none' stroke='white' stroke-width='2.2' stroke-linejoin='round'/></svg>",
  },
};

export const viewport: Viewport = {
  themeColor: "#ffffff",
};

/**
 * Applies a stored theme before first paint so a dark-mode reader never sees a
 * light flash. No stored choice means light — the OS preference is not read.
 */
const BOOT_THEME = `try{var t=localStorage.getItem("aidetector-theme");var dark=t==="dark";document.documentElement.dataset.theme=dark?"dark":"light";var color=dark?"#0e1116":"#ffffff";function paint(){var m=document.querySelector('meta[name="theme-color"]');if(m)m.setAttribute("content",color)}paint();document.addEventListener("DOMContentLoaded",paint)}catch(e){}`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: BOOT_THEME }} />
      </head>
      <body>
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <ConnectionProvider>
          <header className="topbar">
            <div className="wrap inner">
              <BrandLink />
              <Nav />
              <ThemeToggle />
              <AccountMenu />
            </div>
          </header>
          <main id="main">
            <AuthGate>{children}</AuthGate>
          </main>
          <footer className="sitefoot">
            <div className="wrap inner">
              <span className="brand-sm">
                aidetector<span className="dot">.</span>
              </span>
              <span className="foot-note">
                Active scanner. Only ever point it at a target you own or are
                authorized to test.
              </span>
              <FooterLinks />
            </div>
          </footer>
        </ConnectionProvider>
      </body>
    </html>
  );
}
