import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Scan",
};

export default function ScanLayout({ children }: { children: React.ReactNode }) {
  return children;
}
