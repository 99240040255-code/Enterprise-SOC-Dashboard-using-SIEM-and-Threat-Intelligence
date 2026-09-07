import "./globals.css";

export const metadata = {
  title: "Aegis SOC | Security Operations Center",
  description: "Real-time security telemetry and threat intelligence operations dashboard",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
