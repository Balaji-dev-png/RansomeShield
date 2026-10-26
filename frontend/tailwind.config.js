/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#06090F",           // 60% Dominant: Pitch cyber black
          card: "#0D131F",          // 30% Secondary: Deep slate panel
          cardHover: "#121A2B",     // Secondary hover
          border: "#1C283F",        // Structural boundary lines
          borderGlow: "#253452",
          muted: "#64748B",         // Subdued meta text
          text: "#E2E8F0",          // Crisp primary text
          
          // 10% Accents & Threat Indicators
          alert: "#EF4444",         // High-contrast alert red (Decapitation/Crypto)
          alertBg: "rgba(239, 68, 68, 0.12)",
          alertBorder: "rgba(239, 68, 68, 0.35)",
          
          warning: "#F59E0B",       // Threat amber (Elevated entropy / Suspicious)
          warningBg: "rgba(245, 158, 11, 0.12)",
          
          success: "#10B981",       // Mitigated emerald (Restored / Canary Armed)
          successBg: "rgba(16, 185, 129, 0.12)",
          
          neon: "#06B6D4",          // Telemetry Cyan / Radar pulse
          neonBg: "rgba(6, 182, 212, 0.12)",
        },
      },
      fontFamily: {
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "Courier New",
          "monospace",
        ],
      },
      animation: {
        "pulse-fast": "pulse 1.2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "ping-slow": "ping 2s cubic-bezier(0, 0, 0.2, 1) infinite",
        "radar-sweep": "radar 4s linear infinite",
      },
      keyframes: {
        radar: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
      },
    },
  },
  plugins: [],
};

