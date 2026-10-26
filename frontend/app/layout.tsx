import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RansomShield · EDR SOC Command Center",
  description:
    "Real-time Endpoint Detection & Response dashboard for canary tripwires, Shannon entropy analysis, and instant OS process decapitation.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-cyber-bg text-cyber-text min-h-screen cyber-grid antialiased">
        {children}
      </body>
    </html>
  );
}

