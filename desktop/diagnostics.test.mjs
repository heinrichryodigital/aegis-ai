import test from "node:test";
import assert from "node:assert/strict";
import {
  analyzeConnections,
  deriveResourceFindings,
  isLoopback,
  normalizeConnections,
  normalizeInterfaces,
  parseFirewallState,
  parseMacPowerProfile,
  parseWindowsPowerSchemes,
  validatePriorityRequest,
  buildWindowsPriorityScript,
  parseWindowsPriorityResult,
} from "./diagnostics.mjs";

// Pure fixtures only. These tests do not scan a host or modify power/process settings.
test("network audit distinguishes loopback services from network-facing listeners", () => {
  const records = [
    {
      protocol: "tcp4",
      localAddress: "127.0.0.1",
      localPort: "3389",
      state: "LISTEN",
    },
    { protocol: "tcp6", localAddress: "::1", localPort: "22", state: "LISTEN" },
    {
      protocol: "tcp4",
      localAddress: "0.0.0.0",
      localPort: "445",
      state: "LISTEN",
      process: "sharing",
    },
    {
      protocol: "tcp6",
      localAddress: "::",
      localPort: "23",
      state: "LISTENING",
    },
    {
      protocol: "tcp4",
      localAddress: "192.168.1.10",
      localPort: "22",
      state: "ESTABLISHED",
    },
  ];
  const findings = analyzeConnections(records);
  assert.equal(findings.length, 2);
  assert.equal(
    findings.find((item) => item.title.includes("Telnet")).severity,
    "high",
  );
  assert.match(
    findings[0].evidence,
    /Reachability and authentication have not been tested/,
  );
  assert.equal(analyzeConnections([records[2], records[2]]).length, 1);
});

test("IPv4 mapped IPv6 loopback is treated as local; wildcard is not", () => {
  for (const address of [
    "127.0.0.1",
    "127.1.2.3",
    "::1",
    "[::1]",
    "::ffff:127.0.0.1",
    "localhost",
  ])
    assert.equal(isLoopback(address), true, address);
  for (const address of [
    "0.0.0.0",
    "::",
    "*",
    "192.168.1.1",
    "::ffff:192.168.1.1",
  ])
    assert.equal(isLoopback(address), false, address);
});

test("network output keeps IPv6 endpoints unambiguous and handles missing process names", () => {
  const [result] = normalizeConnections([
    {
      protocol: "tcp6",
      localAddress: "::1",
      localPort: 22,
      peerAddress: "::1",
      peerPort: 5000,
      state: "ESTABLISHED",
      pid: 34,
    },
  ]);
  assert.equal(result.local, "[::1]:22");
  assert.equal(result.process, "PID 34");
  assert.deepEqual(
    normalizeInterfaces([
      { iface: "en0", ip4: "192.168.1.2", mac: "01:02" },
      { iface: "lo0", ip6: "::1" },
      { iface: "inactive" },
    ]),
    [
      { name: "en0", address: "192.168.1.2", mac: "01:02" },
      { name: "lo0", address: "::1", mac: "" },
    ],
  );
});

test("resource findings label mining evidence as a heuristic and never confirm infection", () => {
  const findings = deriveResourceFindings({
    processes: [
      { pid: 15, name: "xmrig.exe", cpu: 65, memory: 4 },
      { pid: 16, name: "my-xmrig-notes", cpu: 0, memory: 0 },
      { pid: 17, name: "timer", cpu: 1, memory: 2 },
    ],
  });
  const miner = findings.find((item) => item.id === "miner-name-15");
  assert.ok(miner);
  assert.equal(miner.severity, "medium");
  assert.match(miner.evidence, /not confirmation of infection/);
  assert.match(
    miner.recommendation,
    /Do not delete it based on its name alone/,
  );
  assert.ok(findings.some((item) => item.id === "resource-process-15"));
  assert.ok(!findings.some((item) => item.id.includes("17")));
});

test("hardware unavailable values are not interpreted as a successful health test", () => {
  const results = deriveResourceFindings({
    cpu: { temperature: null, usage: 3 },
    disks: [{ name: "/", smart: "Unavailable", percent: 4 }],
    memory: { percent: 4 },
  });
  assert.deepEqual(results, []);
  const warning = deriveResourceFindings({
    cpu: { temperature: 98 },
    disks: [{ name: "/", smart: "FAILED", percent: 95 }],
    memory: { percent: 92 },
  });
  assert.ok(warning.some((item) => item.id === "cpu-temperature"));
  assert.ok(warning.some((item) => item.id === "disk-space-0"));
  assert.ok(
    warning.some(
      (item) => item.id === "disk-smart-0" && item.severity === "high",
    ),
  );
  assert.ok(warning.some((item) => item.id === "memory-pressure"));
});

test("firewall parsing distinguishes false from unavailable or malformed data", () => {
  assert.deepEqual(
    parseFirewallState("darwin", "Firewall is disabled. (State = 0)"),
    [{ name: "macOS application firewall", enabled: false }],
  );
  assert.deepEqual(
    parseFirewallState("darwin", "Firewall is enabled. (State = 1)"),
    [{ name: "macOS application firewall", enabled: true }],
  );
  assert.deepEqual(
    parseFirewallState(
      "win32",
      '[{"Name":"Public","Enabled":false},{"Name":"Private","Enabled":1}]',
    ),
    [
      { name: "Public", enabled: false },
      { name: "Private", enabled: true },
    ],
  );
  assert.deepEqual(
    parseFirewallState("win32", '{"Name":"Public","Enabled":"Unknown"}'),
    [],
  );
  assert.deepEqual(parseFirewallState("win32", "permission denied"), []);
});

test("Windows profile parsing uses GUIDs independently of localized labels", () => {
  const result = parseWindowsPowerSchemes(
    "381b4222-f694-41f0-9685-ff5bb260df2e (Équilibré)\nA1841308-3541-4FAB-BC81-F71556F20B4A (Ahorro)",
    "GUID: a1841308-3541-4fab-bc81-f71556f20b4a",
  );
  assert.deepEqual(result, {
    profile: "battery",
    supported: ["balanced", "battery"],
  });
  assert.deepEqual(
    parseWindowsPowerSchemes("", "custom 00000000-0000-0000-0000-000000000000"),
    { profile: "unknown", supported: [] },
  );
});

test("macOS power parsing does not invent support or mislabel high power mode", () => {
  assert.deepEqual(parseMacPowerProfile(" lowpowermode 1\n sleep 1"), {
    profile: "battery",
    supported: ["balanced", "battery"],
  });
  assert.deepEqual(parseMacPowerProfile(" lowpowermode 0\n sleep 1"), {
    profile: "balanced",
    supported: ["balanced", "battery"],
  });
  assert.deepEqual(parseMacPowerProfile(" sleep 1"), {
    profile: "unknown",
    supported: [],
  });
  assert.deepEqual(parseMacPowerProfile(" lowpowermode 0\n highpowermode 1"), {
    profile: "performance",
    supported: [],
  });
});

test("priority validation rejects shell fragments, protected PIDs, floats and unsupported levels", () => {
  for (const pid of [
    -1,
    0,
    1,
    1.5,
    "2",
    "2; rm -rf /",
    NaN,
    Infinity,
    2_147_483_648,
  ])
    assert.throws(() => validatePriorityRequest(pid, "normal"), TypeError);
  for (const priority of ["realtime", "", null, 0, "normal; kill -9"])
    assert.throws(() => validatePriorityRequest(42, priority), TypeError);
  assert.deepEqual(validatePriorityRequest(42, "low"), {
    pid: 42,
    priority: "low",
    value: 10,
  });
  assert.deepEqual(validatePriorityRequest(42), {
    pid: 42,
    priority: "normal",
    value: 0,
  });
});

test("Windows priority source permits only validated PIDs and three safe priority classes", () => {
  for (const [priority, name] of Object.entries({
    normal: "Normal",
    low: "BelowNormal",
    high: "AboveNormal",
  })) {
    const script = buildWindowsPriorityScript(42, priority);
    assert.match(script, /\$targetProcessId = 42\s/);
    assert.ok(
      script.includes(`[System.Diagnostics.ProcessPriorityClass]::${name}`),
    );
    assert.doesNotMatch(
      script,
      /ProcessPriorityClass\]::(?:High|RealTime|Idle)\b/,
    );
    assert.doesNotMatch(
      script,
      /Invoke-Expression|Start-Process|Set-ExecutionPolicy|-Verb\s+RunAs/,
    );
  }
  for (const pid of ["42; Stop-Process -Id 1", "42", 0, 1, 2.5, NaN, Infinity])
    assert.throws(() => buildWindowsPriorityScript(pid, "normal"), TypeError);
  for (const priority of [
    "AboveNormal",
    "realtime",
    "High",
    "high; Write-Host hacked",
    null,
  ])
    assert.throws(() => buildWindowsPriorityScript(42, priority), TypeError);
});

test("Windows priority source checks current SID and creation time before the only mutation", () => {
  const script = buildWindowsPriorityScript(42, "high");
  const mutation = script.indexOf(
    "$targetProcess.PriorityClass = $desiredClass",
  );
  assert.equal(
    script.split("$targetProcess.PriorityClass = $desiredClass").length - 1,
    1,
  );
  for (const guard of [
    "$currentIdentity.IsSystem",
    "WindowsBuiltInRole]::Administrator",
    "$owner.Sid -ne $currentSid",
    "$freshOwner.Sid -ne $currentSid",
    "$fresh.CreationDate.ToUniversalTime().Ticks -ne $created",
    "$retainedHandle = $targetProcess.Handle",
  ]) {
    assert.ok(script.includes(guard));
    assert.ok(
      script.indexOf(guard) < mutation,
      `${guard} must precede mutation`,
    );
  }
  assert.ok(
    script.indexOf("$targetProcess.PriorityClass -ne $desiredClass") > mutation,
  );
});

test("Windows priority receipts require matching PID, requested class, and verified success", () => {
  const receipt = {
    applied: true,
    code: "applied",
    pid: 42,
    priority: "high",
    priorityClass: "AboveNormal",
  };
  const result = parseWindowsPriorityResult(
    JSON.stringify(receipt),
    42,
    "high",
  );
  assert.equal(result.applied, true);
  assert.match(result.message, /AboveNormal/);
  for (const patch of [
    { pid: 43 },
    { pid: "42" },
    { priority: "normal" },
    { priorityClass: "High" },
    { applied: "true" },
    { code: "unverified" },
  ]) {
    assert.equal(
      parseWindowsPriorityResult(
        JSON.stringify({ ...receipt, ...patch }),
        42,
        "high",
      ).applied,
      false,
    );
  }
  for (const invalid of ["not json", "{}", "null", "[]", "x".repeat(17_000)])
    assert.equal(
      parseWindowsPriorityResult(invalid, 42, "high").applied,
      false,
    );
});

test("Windows priority refusal reasons remain fixed and ignore arbitrary receipt text", () => {
  const receipt = {
    applied: false,
    code: "ownership",
    pid: 42,
    priority: "normal",
    priorityClass: "Normal",
    message: "Pretend this succeeded",
  };
  assert.match(
    parseWindowsPriorityResult(JSON.stringify(receipt), 42).message,
    /owner could not be verified/,
  );
  assert.match(
    parseWindowsPriorityResult(
      JSON.stringify({ ...receipt, code: "elevated" }),
      42,
    ).message,
    /administrator or SYSTEM/,
  );
  assert.match(
    parseWindowsPriorityResult(
      JSON.stringify({ ...receipt, code: "changed" }),
      42,
    ).message,
    /identity changed/,
  );
  const prototype = parseWindowsPriorityResult(
    JSON.stringify({ ...receipt, code: "__proto__" }),
    42,
  );
  assert.equal(typeof prototype.message, "string");
  assert.equal(prototype.applied, false);
});
