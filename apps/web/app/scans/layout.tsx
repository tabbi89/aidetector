import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Scans",
};

export default function ScansLayout({ children }: { children: React.ReactNode }) {
  return children;
}
