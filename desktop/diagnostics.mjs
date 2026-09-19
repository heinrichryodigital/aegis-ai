import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

// API references: https://systeminformation.io/{cpu,memory,processes,filesystem,network}.html
// https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
// macOS: the installed `man pmset`; no sudo, shell, or authorization dialog is used.
// https://nodejs.org/api/os.html#ossetprioritypid-priority
const execFileAsync = promisify(execFile);
const PROFILE_GUIDS = Object.freeze({
  balanced: "381b4222-f694-41f0-9685-ff5bb260df2e",
  performance: "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
  battery: "a1841308-3541-4fab-bc81-f71556f20b4a",
});
const BASE_LIMITATIONS = [
  "This is a local diagnostic snapshot, not proof that the device is free of malware or surveillance.",
  "Resource and process-name findings are heuristics. Legitimate software can use substantial resources or run mining workloads.",
  "Physical RAM integrity requires a separate offline memory diagnostic; memory usage does not measure RAM health.",
];
const NETWORK_LIMITATIONS = [
  "This audit reads this device’s interfaces, listening sockets, connections, and firewall state only. It does not scan other network devices.",
  "A listening socket does not prove external reachability; firewall rules, router settings, and network segmentation can block it.",
  "A connection snapshot cannot determine whether Wi-Fi is being spied on, verify remote software versions, or detect every intrusion.",
];

const number = (value, fallback = 0) =>
  Number.isFinite(Number(value)) ? Number(value) : fallback;
const percent = (value) =>
  Math.round(Math.min(100, Math.max(0, number(value))) * 10) / 10;
const array = (value) => (Array.isArray(value) ? value : []);
const label = (value) =>
  String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, 300);
const finding = (id, title, severity, category, evidence, recommendation) => ({
  id,
  title,
  severity,
  category,
  evidence,
  recommendation,
});

async function command(file, args) {
  const { stdout } = await execFileAsync(file, args, {
    timeout: 12_000,
    windowsHide: true,
    maxBuffer: 2 * 1024 * 1024,
    encoding: "utf8",
  });
  return stdout;
}

function windowsTool(name) {
  // Avoid current-directory executable resolution for system management tools.
  return path.win32.join(
    process.env.SystemRoot || "C:\\Windows",
    "System32",
    name,
  );
}

async function readSafely(name, fn, fallback, limitations) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(fn),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("timed out")), 15_000);
      }),
    ]);
  } catch {
    limitations.push(
      `${name} is unavailable or permission restricted; this check is incomplete.`,
    );
    return fallback;
  } finally {
    clearTimeout(timer);
  }
}

export function normalizeInterfaces(raw) {
  return array(raw)
    .filter((item) => item.ip4 || item.ip6)
    .map((item) => ({
      name: label(item.ifaceName || item.iface),
      address: label(item.ip4 || item.ip6),
      mac: label(item.mac),
    }));
}

const endpoint = (address, port) =>
  `${String(address ?? "").includes(":") ? `[${label(address)}]` : label(address)}:${label(port)}`;

export function normalizeConnections(raw) {
  return array(raw).map((item) => ({
    protocol: label(item.protocol),
    local: endpoint(item.localAddress, item.localPort),
    remote: endpoint(item.peerAddress, item.peerPort),
    state: label(item.state),
    process: label(
      item.process ||
        (Number(item.pid) > 0 ? `PID ${item.pid}` : "Unavailable"),
    ),
  }));
}

export function isLoopback(address) {
  const host = String(address ?? "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .split("%")[0];
  return (
    host === "localhost" ||
    host === "::1" ||
    host === "0:0:0:0:0:0:0:1" ||
    /^127(?:\.\d{1,3}){3}$/.test(host) ||
    /^::ffff:127(?:\.\d{1,3}){3}$/.test(host)
  );
}

export function analyzeConnections(raw) {
  const findings = [];
  const seen = new Set();
  const serviceNames = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    139: "NetBIOS",
    445: "SMB file sharing",
    3389: "Remote Desktop",
    5900: "screen sharing",
    6379: "Redis",
    27017: "MongoDB",
  };
  for (const item of array(raw)) {
    const port = Number(item.localPort);
    if (
      !/^LISTEN(?:ING)?$/i.test(item.state || "") ||
      isLoopback(item.localAddress) ||
      !serviceNames[port]
    )
      continue;
    const key = `${label(item.localAddress)}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(
      finding(
        `network-listener-${key}`,
        `${serviceNames[port]} accepts connections on a network interface`,
        [21, 23].includes(port) ? "high" : "medium",
        "network",
        `${label(item.protocol)} ${endpoint(item.localAddress, port)} is listening${item.process ? ` (${label(item.process)})` : ""}. Reachability and authentication have not been tested.`,
        [21, 23].includes(port)
          ? "Disable the service if unused; use an encrypted alternative and restrict access with the system firewall."
          : "Verify that this service is intentional, install its updates, and restrict it to trusted devices in the system firewall.",
      ),
    );
  }
  return findings;
}

export function deriveResourceFindings({
  cpu = {},
  memory = {},
  disks = [],
  processes = [],
} = {}) {
  const findings = [];
  if (number(cpu.usage) >= 90)
    findings.push(
      finding(
        "cpu-pressure",
        "High CPU use in this sample",
        "medium",
        "performance",
        `CPU usage is ${percent(cpu.usage)}%. A single sample cannot establish sustained load.`,
        "Review the process list and repeat the measurement while the device is idle. Close an identified app normally if it is no longer needed.",
      ),
    );
  if (number(memory.percent) >= 90)
    findings.push(
      finding(
        "memory-pressure",
        "Memory use is high",
        "medium",
        "performance",
        `${percent(memory.percent)}% of physical memory is in active use.`,
        "Review the largest apps, reduce unused tabs, and check again. High usage alone does not indicate defective RAM or malware.",
      ),
    );
  if (cpu.temperature != null && number(cpu.temperature) >= 90)
    findings.push(
      finding(
        "cpu-temperature",
        "CPU temperature deserves attention",
        "medium",
        "hardware",
        `The available CPU sensor reports ${number(cpu.temperature)} °C; safe operating limits vary by processor.`,
        "Check airflow, reduce sustained workloads, and compare the reading with the device manufacturer’s thermal guidance.",
      ),
    );
  for (const [index, disk] of disks.entries()) {
    if (number(disk.percent) >= 90)
      findings.push(
        finding(
          `disk-space-${index}`,
          `Low free space on ${label(disk.name)}`,
          "medium",
          "storage",
          `${percent(disk.percent)}% of the volume is used.`,
          "Review large files and app caches. Back up important files before removing anything; use the cleanup preview to choose eligible files.",
        ),
      );
    if (/^(?:bad|fail(?:ed|ing)?|pred fail|caution)$/i.test(disk.smart || ""))
      findings.push(
        finding(
          `disk-smart-${index}`,
          "Drive reports a hardware warning",
          "high",
          "hardware",
          `${label(disk.name)} reports SMART status: ${label(disk.smart)}.`,
          "Back up important files now and use the drive manufacturer’s diagnostic utility. Do not run a destructive repair.",
        ),
      );
  }
  for (const item of processes) {
    if (
      /(?:^|[\s._-])(?:xmrig|xmr-stak|cpuminer|ethminer|nbminer|t-rex|lolminer|ccminer)(?:$|[\s._-])/i.test(
        item.name || "",
      )
    ) {
      findings.push(
        finding(
          `miner-name-${item.pid}`,
          "Mining-related process name needs review",
          "medium",
          "security",
          `${label(item.name)} (PID ${item.pid}) matches a mining-tool name. This is a name heuristic, not confirmation of infection or unauthorized mining.`,
          "If you did not intentionally install it, inspect its publisher and file location and scan the executable with an updated antivirus. Do not delete it based on its name alone.",
        ),
      );
    }
    if (number(item.cpu) >= 50 || number(item.memory) >= 15)
      findings.push(
        finding(
          `resource-process-${item.pid}`,
          `${label(item.name)} is using substantial resources`,
          "low",
          "performance",
          `PID ${item.pid}: ${percent(item.cpu)}% CPU and ${percent(item.memory)}% memory in this sample.`,
          "Check whether this app is doing expected work. Save your work before closing it; use a lower priority only for a process you recognize.",
        ),
      );
  }
  return findings;
}

export function parseFirewallState(platform, stdout) {
  if (platform === "darwin") {
    const match = String(stdout).match(/State\s*=\s*([012])/i);
    return match
      ? [{ name: "macOS application firewall", enabled: match[1] !== "0" }]
      : [];
  }
  if (platform === "win32") {
    try {
      const data = JSON.parse(String(stdout).replace(/^\uFEFF/, ""));
      return (Array.isArray(data) ? data : [data])
        .filter(
          (item) =>
            item &&
            (typeof item.Enabled === "boolean" ||
              [0, 1].includes(item.Enabled)),
        )
        .map((item) => ({
          name: label(item.Name),
          enabled: item.Enabled === true || item.Enabled === 1,
        }));
    } catch {
      return [];
    }
  }
  return [];
}

async function readFirewall(limitations) {
  const result = await readSafely(
    "Firewall state",
    async () => {
      if (process.platform === "darwin")
        return parseFirewallState(
          "darwin",
          await command("/usr/libexec/ApplicationFirewall/socketfilterfw", [
            "--getglobalstate",
          ]),
        );
      if (process.platform === "win32")
        return parseFirewallState(
          "win32",
          await command(
            windowsTool("WindowsPowerShell\\v1.0\\powershell.exe"),
            [
              "-NoLogo",
              "-NoProfile",
              "-NonInteractive",
              "-Command",
              "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress",
            ],
          ),
        );
      return [];
    },
    [],
    limitations,
  );
  if (!result.length)
    limitations.push(
      "The operating system firewall state could not be determined.",
    );
  return result
    .filter((item) => !item.enabled)
    .map((item) =>
      finding(
        `firewall-${item.name}`,
        `${item.name} is disabled`,
        "high",
        "network",
        "The operating system reports this firewall profile as disabled. Other security products and network protections were not assessed.",
        "Review the system firewall settings and enable protection for the relevant network profile.",
      ),
    );
}

async function collectNetwork(si, limitations) {
  const [interfaces, gateway, connections] = await Promise.all([
    readSafely(
      "Network interface inventory",
      () => si.networkInterfaces(),
      [],
      limitations,
    ),
    readSafely(
      "Default gateway",
      () => si.networkGatewayDefault(),
      null,
      limitations,
    ),
    readSafely(
      "Network connection inventory",
      () => si.networkConnections(),
      [],
      limitations,
    ),
  ]);
  return {
    rawConnections: connections,
    interfaces: normalizeInterfaces(interfaces),
    gateway: gateway ? label(gateway) : null,
    connections: normalizeConnections(connections),
  };
}

export async function auditNetwork() {
  const limitations = [...NETWORK_LIMITATIONS];
  const si = (await import("systeminformation")).default;
  const [network, firewallFindings] = await Promise.all([
    collectNetwork(si, limitations),
    readFirewall(limitations),
  ]);
  return {
    checkedAt: new Date().toISOString(),
    interfaces: network.interfaces,
    gateway: network.gateway,
    connections: network.connections,
    findings: [
      ...analyzeConnections(network.rawConnections),
      ...firewallFindings,
    ],
    limitations: [...new Set(limitations)],
  };
}

export async function getDiagnostics() {
  const si = (await import("systeminformation")).default;
  const limitations = [...BASE_LIMITATIONS, ...NETWORK_LIMITATIONS];
  // Warm up CPU counters, then sample a bounded interval (the first SI call averages since boot).
  const loadSample = async () => {
    await si.currentLoad();
    await new Promise((resolve) => setTimeout(resolve, 250));
    return si.currentLoad();
  };
  const [
    osInfo,
    rawCpu,
    load,
    temp,
    mem,
    volumes,
    layout,
    battery,
    processList,
    network,
    firewallFindings,
  ] = await Promise.all([
    readSafely(
      "Operating system information",
      () => si.osInfo(),
      {},
      limitations,
    ),
    readSafely("CPU information", () => si.cpu(), {}, limitations),
    readSafely("CPU usage", loadSample, {}, limitations),
    readSafely("CPU temperature", () => si.cpuTemperature(), {}, limitations),
    readSafely("Memory usage", () => si.mem(), {}, limitations),
    readSafely("Volume usage", () => si.fsSize(), [], limitations),
    readSafely(
      "Drive SMART information",
      () => si.diskLayout(),
      [],
      limitations,
    ),
    readSafely("Battery information", () => si.battery(), {}, limitations),
    readSafely("Process inventory", () => si.processes(), {}, limitations),
    collectNetwork(si, limitations),
    readFirewall(limitations),
  ]);
  const temperature = number(temp.main, -1) > 0 ? number(temp.main) : null;
  if (temperature == null)
    limitations.push(
      "CPU temperature is unavailable on this hardware or requires a supported sensor helper; no temperature health claim can be made.",
    );
  const totalMemory = number(mem.total, os.totalmem());
  const usedMemory = Math.min(
    totalMemory,
    number(mem.active, number(mem.used, totalMemory - os.freemem())),
  );
  const cpu = {
    brand: label(
      [rawCpu.manufacturer, rawCpu.brand].filter(Boolean).join(" ") ||
        os.cpus()[0]?.model ||
        "Unknown",
    ),
    usage: percent(load.currentLoad),
    cores: number(rawCpu.cores, os.cpus().length),
    temperature,
  };
  const memory = {
    total: totalMemory,
    used: usedMemory,
    percent: percent(totalMemory > 0 ? (usedMemory / totalMemory) * 100 : 0),
  };
  const disks = array(volumes).map((item) => ({
    name: label(item.mount || item.fs),
    total: number(item.size),
    used: number(item.used),
    percent: percent(item.use),
    smart: label(
      array(layout).find((disk) => disk.device && disk.device === item.fs)
        ?.smartStatus || "Unavailable",
    ),
  }));
  if (
    !disks.length ||
    disks.some((item) => /unknown|unavailable|not supported/i.test(item.smart))
  )
    limitations.push(
      "SMART health could not be reliably matched to one or more volumes. APFS, RAID, USB bridges, and permissions may hide physical-drive health.",
    );
  limitations.push(
    "SMART telemetry is not a full surface test or a guarantee against drive failure.",
  );
  const processes = array(processList.list)
    .map((item) => ({
      pid: number(item.pid),
      name: label(item.name || "Unknown process"),
      cpu: percent(item.cpu),
      memory: percent(item.mem),
    }))
    .sort((a, b) => b.cpu - a.cpu || b.memory - a.memory);
  const physicalWarnings = array(layout)
    .filter((item) =>
      /^(?:bad|fail(?:ed|ing)?|pred fail|caution)$/i.test(
        item.smartStatus || "",
      ),
    )
    .map((item, index) =>
      finding(
        `physical-smart-${index}`,
        "Physical drive reports a hardware warning",
        "high",
        "hardware",
        `${label(item.name || item.device)} reports SMART status: ${label(item.smartStatus)}.`,
        "Back up your files and run the manufacturer’s drive diagnostic.",
      ),
    );
  return {
    platform: process.platform,
    hostname: os.hostname(),
    os: label(
      [
        osInfo.distro || os.type(),
        osInfo.release || os.release(),
        osInfo.arch || os.arch(),
      ]
        .filter(Boolean)
        .join(" "),
    ),
    cpu,
    memory,
    disks,
    battery: {
      available: Boolean(battery.hasBattery),
      percent: percent(battery.percent),
      charging: Boolean(battery.isCharging),
    },
    processes,
    network: {
      interfaces: network.interfaces,
      gateway: network.gateway,
      connections: network.connections,
    },
    findings: [
      ...deriveResourceFindings({ cpu, memory, disks, processes }),
      ...physicalWarnings,
      ...analyzeConnections(network.rawConnections),
      ...firewallFindings,
    ],
    limitations: [...new Set(limitations)],
  };
}

export function parseWindowsPowerSchemes(list, active) {
  const listText = String(list).toLowerCase();
  const activeGuid = String(active)
    .toLowerCase()
    .match(/[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}/)?.[0];
  return {
    profile:
      Object.keys(PROFILE_GUIDS).find(
        (profile) => PROFILE_GUIDS[profile] === activeGuid,
      ) || "unknown",
    supported: Object.keys(PROFILE_GUIDS).filter((profile) =>
      listText.includes(PROFILE_GUIDS[profile]),
    ),
  };
}

export function parseMacPowerProfile(stdout) {
  const low = String(stdout).match(/^\s*lowpowermode\s+([01])\s*$/m);
  const high = /^\s*highpowermode\s+1\s*$/m.test(String(stdout));
  return {
    profile: high
      ? "performance"
      : low
        ? low[1] === "1"
          ? "battery"
          : "balanced"
        : "unknown",
    supported: low && !high ? ["balanced", "battery"] : [],
  };
}

export async function getPowerProfile() {
  try {
    if (process.platform === "win32") {
      const [list, active] = await Promise.all([
        command(windowsTool("powercfg.exe"), ["/list"]),
        command(windowsTool("powercfg.exe"), ["/getactivescheme"]),
      ]);
      const result = parseWindowsPowerSchemes(list, active);
      return {
        ...result,
        canApply: result.supported.length > 0,
        message:
          "Only existing Windows built-in power schemes can be selected. Organization policy may prevent changes.",
      };
    }
    if (process.platform === "darwin") {
      const result = parseMacPowerProfile(
        await command("/usr/bin/pmset", ["-g"]),
      );
      const canApply = process.getuid?.() === 0 && result.supported.length > 0;
      return {
        ...result,
        canApply,
        message: canApply
          ? "Balanced disables Low Power Mode; battery enables it for all power sources. High Power Mode must be managed in System Settings on supported Macs."
          : "Read-only power status. Use System Settings → Battery or Energy to change the Mac’s energy mode; this app does not request elevated privileges.",
      };
    }
    return {
      profile: "unknown",
      supported: [],
      canApply: false,
      message:
        "Power controls are available on Windows and supported macOS devices only.",
    };
  } catch {
    return {
      profile: "unknown",
      supported: [],
      canApply: false,
      message:
        "The current power profile could not be read. Use your operating system’s power settings.",
    };
  }
}

export async function setPowerProfile(profile = "balanced") {
  if (!Object.hasOwn(PROFILE_GUIDS, profile))
    return {
      applied: false,
      profile,
      message: "Choose balanced, performance, or battery.",
    };
  try {
    const current = await getPowerProfile();
    if (!current.supported.includes(profile))
      return {
        applied: false,
        profile,
        message:
          profile === "performance" && process.platform === "darwin"
            ? "High Power Mode depends on the Mac model. Select it in System Settings if supported."
            : "This built-in profile is not available on this device; no new power schemes were created.",
      };
    if (!current.canApply)
      return { applied: false, profile, message: current.message };
    if (process.platform === "win32")
      await command(windowsTool("powercfg.exe"), [
        "/setactive",
        PROFILE_GUIDS[profile],
      ]);
    else if (process.platform === "darwin")
      await command("/usr/bin/pmset", [
        "-a",
        "lowpowermode",
        profile === "battery" ? "1" : "0",
      ]);
    else
      return {
        applied: false,
        profile,
        message: "This operating system is not supported.",
      };
    const result = await getPowerProfile();
    const applied = result.profile === profile;
    return {
      applied,
      profile,
      message: applied
        ? `${profile[0].toUpperCase() + profile.slice(1)} mode applied.${process.platform === "darwin" ? " Low Power Mode setting applies to all power sources." : ""}`
        : "The command finished, but the new profile could not be verified. Check the system power settings.",
    };
  } catch {
    return {
      applied: false,
      profile,
      message:
        "The operating system denied or could not complete the change. No elevation was requested; use the system power settings.",
    };
  }
}

export function validatePriorityRequest(pid, priority = "normal") {
  if (!Number.isSafeInteger(pid) || pid <= 1 || pid > 2_147_483_647)
    throw new TypeError("A process ID must be an integer greater than 1.");
  if (!["normal", "low", "high"].includes(priority))
    throw new TypeError("Priority must be normal, low, or high.");
  return { pid, priority, value: { normal: 0, low: 10, high: -5 }[priority] };
}

const WINDOWS_PRIORITY_CLASSES = Object.freeze({
  normal: "Normal",
  low: "BelowNormal",
  high: "AboveNormal",
});

// Windows ownership is checked using the SID, not a localized or truncated username:
// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/getownersid-method-in-class-win32-process
// https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsprincipal.isinrole
// https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.priorityclass
export function buildWindowsPriorityScript(pid, priority = "normal") {
  const request = validatePriorityRequest(pid, priority);
  const priorityClass = WINDOWS_PRIORITY_CLASSES[request.priority];
  // Only a validated integer and fixed enum literals are substituted. No user commands,
  // process names, paths, or environment-supplied scripts can enter PowerShell source.
  return `$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Invoke-AegisPriorityChange {
  $targetProcessId = ${request.pid}
  $requestedPriority = '${request.priority}'
  $desiredClass = [System.Diagnostics.ProcessPriorityClass]::${priorityClass}
  $result = @{ applied = $false; code = 'unavailable'; pid = $targetProcessId; priority = $requestedPriority; priorityClass = '${priorityClass}' }
  $currentIdentity = $null
  $targetProcess = $null
  try {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList $currentIdentity
    if ($currentIdentity.IsSystem -or $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
      $result.code = 'elevated'
      return $result
    }
    if ($null -eq $currentIdentity.User -or [string]::IsNullOrWhiteSpace($currentIdentity.User.Value)) {
      $result.code = 'ownership'
      return $result
    }
    $currentSid = $currentIdentity.User.Value
    $targetProcess = [System.Diagnostics.Process]::GetProcessById($targetProcessId)
    $retainedHandle = $targetProcess.Handle
    if ($retainedHandle -eq [IntPtr]::Zero -or $targetProcess.HasExited) {
      $result.code = 'changed'
      return $result
    }
    $initial = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $targetProcessId)
    if ($null -eq $initial -or $null -eq $initial.CreationDate) {
      $result.code = 'ownership'
      return $result
    }
    $created = $initial.CreationDate.ToUniversalTime().Ticks
    $owner = Invoke-CimMethod -InputObject $initial -MethodName GetOwnerSid
    if ($null -eq $owner -or $owner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace($owner.Sid) -or $owner.Sid -ne $currentSid) {
      $result.code = 'ownership'
      return $result
    }
    $fresh = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $targetProcessId)
    if ($null -eq $fresh -or $null -eq $fresh.CreationDate -or $fresh.CreationDate.ToUniversalTime().Ticks -ne $created) {
      $result.code = 'changed'
      return $result
    }
    $freshOwner = Invoke-CimMethod -InputObject $fresh -MethodName GetOwnerSid
    if ($null -eq $freshOwner -or $freshOwner.ReturnValue -ne 0 -or [string]::IsNullOrWhiteSpace($freshOwner.Sid) -or $freshOwner.Sid -ne $currentSid) {
      $result.code = 'ownership'
      return $result
    }
    if ($targetProcess.HasExited) {
      $result.code = 'changed'
      return $result
    }
    $targetProcess.PriorityClass = $desiredClass
    $targetProcess.Refresh()
    if ($targetProcess.HasExited -or $targetProcess.PriorityClass -ne $desiredClass) {
      $result.code = 'unverified'
      return $result
    }
    $result.applied = $true
    $result.code = 'applied'
    return $result
  } catch {
    $result.code = 'unavailable'
    return $result
  } finally {
    if ($null -ne $targetProcess) { $targetProcess.Dispose() }
    if ($null -ne $currentIdentity) { $currentIdentity.Dispose() }
  }
}
Invoke-AegisPriorityChange | ConvertTo-Json -Compress`;
}

export function parseWindowsPriorityResult(stdout, pid, priority = "normal") {
  const request = validatePriorityRequest(pid, priority);
  const fallback = {
    applied: false,
    pid,
    priority,
    message:
      "Windows process tuning is unavailable because ownership or the result could not be verified. No elevation was requested.",
  };
  if (typeof stdout !== "string" || stdout.length > 16_384) return fallback;
  try {
    const result = JSON.parse(stdout.replace(/^\uFEFF/, "").trim());
    if (
      !result ||
      Array.isArray(result) ||
      result.pid !== request.pid ||
      result.priority !== request.priority ||
      result.priorityClass !== WINDOWS_PRIORITY_CLASSES[priority] ||
      typeof result.applied !== "boolean"
    )
      return fallback;
    if (result.applied === true && result.code === "applied")
      return {
        applied: true,
        pid,
        priority,
        message: `Process ${pid} now uses Windows ${WINDOWS_PRIORITY_CLASSES[priority]} priority. This adjusts scheduling; it does not reserve CPU or RAM.`,
      };
    if (result.applied) return fallback;
    const messages = {
      elevated:
        "Process tuning is disabled while this app runs as administrator or SYSTEM. Run it as your regular, unelevated user.",
      ownership:
        "Windows process tuning is unavailable for this process because its owner could not be verified as your current user.",
      changed:
        "The process exited or its identity changed before tuning. Refresh the process list and try again.",
      unverified:
        "Windows could not verify the resulting process priority. Check the process in Task Manager.",
      unavailable:
        "The process exited, Windows denied access, or local ownership checks are unavailable. No elevation was requested.",
    };
    return {
      ...fallback,
      message:
        typeof result.code === "string" && Object.hasOwn(messages, result.code)
          ? messages[result.code]
          : fallback.message,
    };
  } catch {
    return fallback;
  }
}

export async function setProcessPriority(pid, priority = "normal") {
  let request;
  try {
    request = validatePriorityRequest(pid, priority);
  } catch (error) {
    return { applied: false, message: error.message, pid, priority };
  }
  if (process.platform === "win32") {
    try {
      const output = await command(
        windowsTool("WindowsPowerShell\\v1.0\\powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          buildWindowsPriorityScript(pid, priority),
        ],
      );
      return parseWindowsPriorityResult(output, pid, priority);
    } catch {
      return {
        applied: false,
        pid,
        priority,
        message:
          "Windows could not complete or verify process tuning. Use Task Manager to check the current priority; this app did not request elevated permissions.",
      };
    }
  }
  if (!["darwin", "linux"].includes(process.platform))
    return {
      applied: false,
      pid,
      priority,
      message:
        "Changing process priority is unavailable here because process ownership cannot be reliably verified. Use the operating system’s process manager.",
    };
  if (process.getuid?.() === 0)
    return {
      applied: false,
      pid,
      priority,
      message:
        "Process tuning is disabled when the app runs as root. Run the app as your regular user.",
    };
  try {
    const owner = (
      await command("/bin/ps", ["-o", "uid=", "-p", String(request.pid)])
    ).trim();
    if (!/^\d+$/.test(owner) || Number(owner) !== process.getuid?.())
      return {
        applied: false,
        pid,
        priority,
        message:
          "This process is unavailable or is not owned by your current user.",
      };
    os.setPriority(request.pid, request.value);
    const applied = os.getPriority(request.pid) === request.value;
    return {
      applied,
      pid,
      priority,
      message: applied
        ? `Process ${pid} priority is now ${priority}. This adjusts scheduling; it does not reserve CPU or RAM. Raising it again may require system permissions.`
        : "The operating system did not retain the requested priority.",
    };
  } catch {
    return {
      applied: false,
      pid,
      priority,
      message:
        "The process exited or the operating system denied this change. Increasing priority may require permissions this app does not request.",
    };
  }
}
