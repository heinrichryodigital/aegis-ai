import type { Diagnostics, Finding, Scan } from "./types";
export const sampleFindings: Finding[] = [
  {
    id: "demo-resource",
    title: "A background app is using significant memory",
    severity: "medium",
    category: "Performance",
    evidence: "Example: creative-studio is using 3.2 GB of memory.",
    recommendation:
      "Save your work and close unused projects. Review the process before changing its priority.",
  },
  {
    id: "demo-service",
    title: "Review a listening remote-access service",
    severity: "low",
    category: "Network",
    evidence: "Example: a remote desktop service is listening on this device.",
    recommendation:
      "Disable remote access if you do not use it, or restrict it with your operating system firewall.",
  },
  {
    id: "demo-engine",
    title: "Install and update a malware engine",
    severity: "info",
    category: "Protection",
    evidence:
      "The desktop app uses a locally installed ClamAV engine. The built-in fallback only identifies the EICAR test file.",
    recommendation:
      "Install ClamAV and update its signatures with freshclam before relying on malware scans.",
  },
];
export const sampleDevice: Diagnostics = {
  platform: "preview",
  hostname: "Example device",
  os: "Desktop preview",
  cpu: { brand: "8-core processor", usage: 18, cores: 8, temperature: 49 },
  memory: { total: 17179869184, used: 6657199308, percent: 39 },
  disks: [
    {
      name: "System drive",
      total: 512110190592,
      used: 221232230400,
      percent: 43,
      smart: "Example: passed",
    },
  ],
  battery: { available: true, percent: 82, charging: false },
  processes: [
    { pid: 101, name: "creative-studio", cpu: 12.4, memory: 20 },
    { pid: 102, name: "Web browser", cpu: 4.2, memory: 8.1 },
    { pid: 103, name: "Window manager", cpu: 1.8, memory: 3.2 },
  ],
  network: {
    interfaces: [{ name: "Wi-Fi (example)", address: "192.0.2.10" }],
    gateway: "192.0.2.1",
    connections: [
      {
        protocol: "TCP",
        local: "192.0.2.10:51812",
        remote: "203.0.113.12:443",
        state: "ESTABLISHED",
        process: "Web browser",
      },
    ],
  },
  findings: sampleFindings,
  limitations: [
    "All values on this screen are examples. Install the desktop app to read your device.",
  ],
};
export const sampleScan = (): Scan => ({
  id: "demo-scan",
  startedAt: new Date().toISOString(),
  finishedAt: new Date().toISOString(),
  root: "Example Downloads",
  scanned: 1248,
  skipped: 3,
  status: "complete",
  engine: "Demo only — no files accessed",
  findings: sampleFindings,
  warnings: [
    "This simulation did not scan your files or assess your security.",
  ],
});
