import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { MongoClient } from "mongodb";

const globalState = globalThis;

const iocSeed = [
  { id: "ioc-otx-001", type: "ip", value: "185.220.101.17", category: "Command & Control", malware: "Cobalt Strike", confidence: 98, source: "AlienVault OTX", firstSeen: "2026-07-19" },
  { id: "ioc-otx-002", type: "ip", value: "45.148.10.22", category: "Credential Access", malware: "RedLine Stealer", confidence: 94, source: "ThreatFox", firstSeen: "2026-07-28" },
  { id: "ioc-otx-003", type: "domain", value: "cdn-update-check.com", category: "Malware Distribution", malware: "QakBot", confidence: 97, source: "AlienVault OTX", firstSeen: "2026-08-01" },
  { id: "ioc-otx-004", type: "hash", value: "b7e23ec29af22b0b4f6d8a7f7e4c9d8a1c2b3d4e5f60718293a4b5c6d7e8f901", category: "Execution", malware: "PowerShell Empire", confidence: 99, source: "ThreatFox", firstSeen: "2026-08-03" },
  { id: "ioc-otx-005", type: "ip", value: "91.240.118.172", category: "Initial Access", malware: "LockBit", confidence: 91, source: "AlienVault OTX", firstSeen: "2026-08-05" },
  { id: "ioc-otx-006", type: "domain", value: "login-m365-auth.net", category: "Phishing", malware: "Lumma", confidence: 89, source: "ThreatFox", firstSeen: "2026-08-07" },
];

const ruleSeed = [
  { id: "rule-lsass", name: "LSASS Process Access", severity: "CRITICAL", tactic: "Credential Access", enabled: true, description: "Detects suspicious access to lsass.exe memory" },
  { id: "rule-ssh", name: "SSH Brute Force", severity: "HIGH", tactic: "Credential Access", enabled: true, description: "Five or more failed attempts from one source in 30 seconds" },
  { id: "rule-dns", name: "Malicious Outbound DNS Query", severity: "HIGH", tactic: "Command & Control", enabled: true, description: "Outbound lookup to a known malicious domain" },
];

function createState() {
  return {
    events: [], alerts: [], blockedIps: new Set(), sshFailures: new Map(), authSeries: [], lastGeneratedAt: Date.now(), iocs: iocSeed, rules: ruleSeed,
    mongoPromise: null, mongoReady: false,
  };
}

const state = globalState.__socDashboardState || (globalState.__socDashboardState = createState());

async function getDatabase() {
  if (!process.env.MONGO_URL) return null;
  if (!state.mongoPromise) {
    state.mongoPromise = MongoClient.connect(process.env.MONGO_URL, { maxPoolSize: 5, serverSelectionTimeoutMS: 900 });
  }
  try {
    const client = await state.mongoPromise;
    state.mongoReady = true;
    return client.db();
  } catch {
    state.mongoPromise = null;
    state.mongoReady = false;
    return null;
  }
}

const pick = (items) => items[Math.floor(Math.random() * items.length)];
const pad = (value) => String(value).padStart(2, "0");
const timestamp = () => new Date().toISOString();

function makeScenario() {
  const scenarios = [
    { source_ip: "185.220.101.17", destination_ip: "10.24.8.15", event_kind: "network", action: "C2 beacon", severity: "CRITICAL", technique: "T1071.001", techniqueName: "Web Protocols", country: "Germany", city: "Frankfurt", malware: "Cobalt Strike", iocType: "ip" },
    { source_ip: "45.148.10.22", destination_ip: "10.24.4.9", event_kind: "authentication", action: "SSH login failure", severity: "HIGH", technique: "T1110", techniqueName: "Brute Force", country: "Romania", city: "Bucharest", malware: "RedLine Stealer", iocType: "ip" },
    { source_ip: "10.24.12.44", destination_ip: "8.8.8.8", event_kind: "process", action: "Process Create", severity: "MEDIUM", technique: "T1059.001", techniqueName: "PowerShell", country: "United States", city: "Ashburn", malware: null, iocType: null },
    { source_ip: "91.240.118.172", destination_ip: "10.24.8.22", event_kind: "network", action: "Suricata ET SCAN", severity: "HIGH", technique: "T1046", techniqueName: "Network Service Scanning", country: "Netherlands", city: "Amsterdam", malware: "LockBit", iocType: "ip" },
    { source_ip: "10.24.7.19", destination_ip: "10.24.8.15", event_kind: "authentication", action: "Windows logon success", severity: "LOW", technique: "T1078", techniqueName: "Valid Accounts", country: "United States", city: "Dallas", malware: null, iocType: null },
    { source_ip: "10.24.9.62", destination_ip: "10.24.4.12", event_kind: "process", action: "Process Create", severity: "MEDIUM", technique: "T1059", techniqueName: "Command and Scripting Interpreter", country: "United States", city: "Seattle", malware: null, iocType: null },
    { source_ip: "10.24.5.33", destination_ip: "cdn-update-check.com", event_kind: "dns", action: "Outbound DNS query", severity: "HIGH", technique: "T1071.004", techniqueName: "DNS", country: "United Kingdom", city: "London", malware: "QakBot", iocType: "domain" },
  ];
  const selected = pick(scenarios);
  const suspicious = selected.event_kind === "process" && Math.random() > 0.45;
  return { ...selected, command_line: suspicious ? "powershell.exe -nop -w hidden -enc JABXAGMAYQByAGU=" : selected.event_kind === "process" ? "svchost.exe -k netsvcs" : null, user: pick(["j.smith", "svc-backup", "a.chen", "SYSTEM"]), parent_process: suspicious ? "winword.exe" : "services.exe" };
}

function enrichEvent(scenario) {
  const event = {
    id: randomUUID(), event_time: timestamp(), source: pick(["sysmon", "auditd", "suricata"]), event_kind: scenario.event_kind,
    action: scenario.action, source_ip: scenario.source_ip, destination_ip: scenario.destination_ip, severity: scenario.severity,
    country: scenario.country, city: scenario.city, technique: scenario.technique, techniqueName: scenario.techniqueName,
    command_line: scenario.command_line, user: scenario.user, parent_process: scenario.parent_process, host: pick(["WIN-DC01", "WEB-PROD-02", "LINUX-APP-01"]),
    file_hash: scenario.iocType === "hash" ? iocSeed[3].value : null, threat_intel_match: false, threat: null,
  };
  const candidates = [event.source_ip, event.destination_ip, event.file_hash];
  const match = state.iocs.find((ioc) => candidates.includes(ioc.value));
  if (match) {
    event.threat_intel_match = true;
    event.threat = { category: match.category, malware: match.malware, confidence: match.confidence, source: match.source, ioc_type: match.type, matched_value: match.value };
    event.severity = match.confidence > 95 ? "CRITICAL" : "HIGH";
  }
  return event;
}

function addAlert(event) {
  const isRuleMatch = event.action === "Process Create" && event.command_line?.includes("-enc") || event.event_kind === "dns" && event.threat_intel_match || event.threat_intel_match;
  if (!isRuleMatch) return;
  const alert = { id: randomUUID(), created_at: event.event_time, event_id: event.id, title: event.threat?.malware ? `${event.threat.malware} indicator detected` : "Suspicious process execution", severity: event.severity, status: "NEW", tactic: event.techniqueName, source_ip: event.source_ip };
  state.alerts.unshift(alert);
  state.alerts = state.alerts.slice(0, 80);
}

async function persistEvents(events) {
  const db = await getDatabase();
  if (!db || !events.length) return;
  try {
    await db.collection("soc_events").insertMany(events, { ordered: false });
    const iocDocs = state.iocs.map((ioc) => ({ ...ioc, _id: ioc.id }));
    await db.collection("soc_iocs").bulkWrite(iocDocs.map((ioc) => ({ updateOne: { filter: { _id: ioc._id }, update: { $setOnInsert: ioc }, upsert: true } })), { ordered: false });
  } catch {
    // The in-process stream remains available if Mongo is restarting.
  }
}

function buildSnapshot(rate) {
  const now = Date.now();
  const count = Math.max(1, Math.min(10, Number(rate) || 4));
  const batch = Array.from({ length: count }, () => enrichEvent(makeScenario()));
  batch.forEach((event) => { state.events.unshift(event); addAlert(event); });
  state.events = state.events.slice(0, 160);
  const success = batch.filter((event) => event.action === "Windows logon success" || event.action === "SSH login success").length;
  const failures = batch.filter((event) => event.action === "SSH login failure").length;
  state.authSeries.push({ time: `${pad(new Date(now).getMinutes())}:${pad(new Date(now).getSeconds())}`, success: success + Math.floor(Math.random() * 5) + 2, failed: failures + Math.floor(Math.random() * 3) });
  state.authSeries = state.authSeries.slice(-14);
  state.lastGeneratedAt = now;
  void persistEvents(batch);
  const matched = state.events.filter((event) => event.threat_intel_match);
  const severityCounts = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].reduce((acc, severity) => ({ ...acc, [severity]: state.events.filter((event) => event.severity === severity).length }), {});
  const attackerMap = new Map();
  matched.forEach((event) => { if (!attackerMap.has(event.source_ip)) attackerMap.set(event.source_ip, { ip: event.source_ip, country: event.country, city: event.city, hits: 0, reputation: event.threat?.confidence || 80 }); attackerMap.get(event.source_ip).hits += 1; });
  const techniques = ["T1059", "T1059.001", "T1110", "T1046", "T1071.001", "T1071.004", "T1078", "T1003"].map((id) => ({ id, name: ({ "T1059": "Command & Scripting", "T1059.001": "PowerShell", T1110: "Brute Force", T1046: "Network Scanning", "T1071.001": "Web Protocols", "T1071.004": "DNS", T1078: "Valid Accounts", T1003: "OS Credential Dumping" }[id]), count: state.events.filter((event) => event.technique === id).length }));
  return { generated_at: timestamp(), eps: count, events: state.events.slice(0, 24), alerts: state.alerts.slice(0, 12), iocs: matched.slice(0, 12), ioc_catalog: state.iocs, rules: state.rules, auth_series: state.authSeries, attackers: [...attackerMap.values()].sort((a, b) => b.hits - a.hits).slice(0, 6), techniques, metrics: { severity: severityCounts, iocMatchPercent: state.events.length ? Math.round((matched.length / state.events.length) * 100) : 0, total: state.events.length, blocked: state.blockedIps.size, mongo: state.mongoReady } };
}

export async function GET(request, { params }) {
  try {
    const segment = (await params)?.path?.join("/") || "";
    if (segment === "health") return NextResponse.json({ ok: true, service: "soc-telemetry", mongo: state.mongoReady });
    if (segment === "telemetry") return NextResponse.json(buildSnapshot(new URL(request.url).searchParams.get("rate")));
    if (segment === "rules") return NextResponse.json({ rules: state.rules });
    return NextResponse.json({ error: "Route not found" }, { status: 404 });
  } catch (error) {
    return NextResponse.json({ error: "Telemetry service unavailable", detail: error.message }, { status: 500 });
  }
}

export async function PATCH(request, { params }) {
  try {
    const segments = (await params)?.path || [];
    if (segments[0] === "alerts" && segments[1]) {
      const body = await request.json();
      const alert = state.alerts.find((item) => item.id === segments[1]);
      if (!alert) return NextResponse.json({ error: "Alert not found" }, { status: 404 });
      alert.status = body.status || alert.status;
      const db = await getDatabase();
      if (db) await db.collection("soc_alerts").updateOne({ _id: alert.id }, { $set: { ...alert, _id: alert.id } }, { upsert: true });
      return NextResponse.json({ alert });
    }
    return NextResponse.json({ error: "Route not found" }, { status: 404 });
  } catch (error) {
    return NextResponse.json({ error: "Unable to update alert", detail: error.message }, { status: 400 });
  }
}

export async function POST(request, { params }) {
  try {
    const segments = (await params)?.path || [];
    if (segments[0] === "actions" && segments[1] === "block-ip") {
      const { ip } = await request.json();
      if (!ip) return NextResponse.json({ error: "IP is required" }, { status: 400 });
      state.blockedIps.add(ip);
      return NextResponse.json({ ok: true, ip, blocked: true });
    }
    return NextResponse.json({ error: "Route not found" }, { status: 404 });
  } catch (error) {
    return NextResponse.json({ error: "Unable to complete action", detail: error.message }, { status: 400 });
  }
}
