// server.js - Dashboard/Agent + Copier SaaS (Clients/Expiry) - Render Ready
import express from "express";
import cors from "cors";
import fs from "fs";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.static(".")); // serves dashboard.html + admin.html from project root

// ================= ENV =================
const PORT = process.env.PORT || 10000;

// protects dashboard/agent endpoints (optional)
const API_KEY = process.env.API_KEY || "";

// protects admin endpoints (recommended)
const ADMIN_KEY = process.env.ADMIN_KEY || "";

// protects master push
const MASTER_KEY = process.env.MASTER_KEY || "";

// ================= Helpers =================
function nowMs() { return Date.now(); }
function readJsonSafe(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const txt = fs.readFileSync(file, "utf8");
    if (!txt.trim()) return fallback;
    return JSON.parse(txt);
  } catch {
    return fallback;
  }
}
function writeJsonSafe(file, obj) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), "utf8");
  fs.renameSync(tmp, file);
}
function randKey(len = 32) {
  return crypto.randomBytes(len).toString("hex"); // 64 chars if len=32
}
function addDurationMs(code) {
  const day = 24 * 60 * 60 * 1000;
  if (code === "M1") return 31 * day;
  if (code === "M3") return 93 * day;
  if (code === "M6") return 186 * day;
  if (code === "Y1") return 366 * day;
  return 31 * day;
}

// ================= Auth =================
function authOk(req) {
  if (!API_KEY) return true;
  return req.get("x-api-key") === API_KEY;
}
function adminOk(req) {
  if (!ADMIN_KEY) return true; // allow if you forgot (لكن لا أنصح)
  return req.get("x-admin-key") === ADMIN_KEY;
}
function masterOk(req) {
  if (!MASTER_KEY) return false;
  return req.get("x-master-key") === MASTER_KEY;
}

// ================= Clients Store =================
const CLIENTS_FILE = "./clients.json";
/**
 * client = {
 *   clientId, fullName, groupId, apiKey,
 *   enabled: true/false,
 *   createdAt, expiresAt,
 *   boundSlaveId: ""  // enforce 1 MT4 account per client
 * }
 */
let clients = readJsonSafe(CLIENTS_FILE, { clients: [] });
function saveClients() { writeJsonSafe(CLIENTS_FILE, clients); }

function findClientByApiKey(apiKey) {
  return (clients.clients || []).find(c => c.apiKey === apiKey) || null;
}
function findClientById(clientId) {
  return (clients.clients || []).find(c => c.clientId === clientId) || null;
}
function clientActive(c) {
  if (!c) return false;
  if (!c.enabled) return false;
  if (Number(c.expiresAt || 0) <= nowMs()) return false;
  return true;
}

// Copier auth: must have valid client API key, not expired, and group match
function requireClient(req, res, groupIdFromReq) {
  const k = (req.get("x-api-key") || "").trim();
  if (!k) {
    res.status(401).json({ ok: false, error: "missing x-api-key" });
    return null;
  }
  const c = findClientByApiKey(k);
  if (!c) {
    res.status(401).json({ ok: false, error: "invalid api key" });
    return null;
  }
  if (!clientActive(c)) {
    res.status(403).json({ ok: false, error: "expired/disabled" });
    return null;
  }
  if (groupIdFromReq && String(c.groupId) !== String(groupIdFromReq)) {
    res.status(403).json({ ok: false, error: "group mismatch" });
    return null;
  }
  return c;
}

// ================= Dashboard/Agent (your existing system) =================
const accounts = new Map(); // accountId -> payload
const commands = new Map(); // accountId -> cmd
let nextCmdId = 1;

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    now: nowMs(),
    accounts: accounts.size,
    commands: commands.size,
  });
});

app.post("/report", (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const b = req.body || {};
  const accountId = String(b.accountId || "");
  if (!accountId) return res.status(400).json({ ok: false, error: "missing accountId" });

  const payload = {
    accountId,
    name: String(b.name || ""),
    login: Number(b.login || 0),
    server: String(b.server || ""),
    currency: String(b.currency || ""),
    leverage: Number(b.leverage || 0),
    ts: nowMs(),
    balance: Number(b.balance || 0),
    equity: Number(b.equity || 0),
    margin: Number(b.margin || 0),
    free: Number(b.free || 0),
    orders: Array.isArray(b.orders) ? b.orders : [],
    stats: b.stats && typeof b.stats === "object" ? b.stats : {},
  };

  accounts.set(accountId, payload);
  res.json({ ok: true });
});

app.get("/command", (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const accountId = String(req.query.accountId || "");
  if (!accountId) return res.status(400).json({ ok: false, error: "missing accountId" });

  const cmd = commands.get(accountId);
  if (!cmd || cmd.status !== "NEW") return res.json({ ok: true, has: false });

  res.json({ ok: true, has: true, command: cmd });
});

app.post("/command_ack", (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const b = req.body || {};
  const accountId = String(b.accountId || "");
  const id = Number(b.id || 0);
  const status = String(b.status || "");
  const errMsg = String(b.errMsg || "");

  if (!accountId || !id || !status) return res.status(400).json({ ok: false, error: "missing fields" });

  const cmd = commands.get(accountId);
  if (cmd && cmd.id === id) {
    cmd.status = status; // DONE | ERR
    cmd.errMsg = errMsg;
    cmd.ackTs = nowMs();
    commands.set(accountId, cmd);
  }
  res.json({ ok: true });
});

app.get("/api/accounts", (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  const out = Array.from(accounts.values()).sort((a, b) => (b.ts - a.ts));
  res.json({ ok: true, now: nowMs(), accounts: out });
});

app.post("/api/panic", (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const b = req.body || {};
  const accountId = String(b.accountId || "");
  const target = String(b.target || "ALL");

  if (accountId === "ALL") {
    for (const accId of accounts.keys()) {
      commands.set(accId, { id: nextCmdId++, type: "PANIC_CLOSE", target, ts: nowMs(), status: "NEW", errMsg: "" });
    }
    return res.json({ ok: true, issued: "ALL" });
  }

  if (!accountId) return res.status(400).json({ ok: false, error: "missing accountId" });

  commands.set(accountId, { id: nextCmdId++, type: "PANIC_CLOSE", target, ts: nowMs(), status: "NEW", errMsg: "" });
  res.json({ ok: true, issued: accountId });
});

// ================= Copier (Events) =================
const COPIER_FILE = "./copier_events.json";
let copier = readJsonSafe(COPIER_FILE, { nextId: 1, events: [] });

function saveCopier() {
  // keep last 50k events max
  if (copier.events.length > 50000) copier.events = copier.events.slice(-50000);
  writeJsonSafe(COPIER_FILE, copier);
}

const SLAVES_FILE = "./slaves.json";
let slaves = readJsonSafe(SLAVES_FILE, { slaves: {} }); // key: group|slaveId -> { lastAckId, lastSeenAt }
function saveSlaves() { writeJsonSafe(SLAVES_FILE, slaves); }

function slaveKey(group, slaveId) {
  return `${group}|${slaveId}`;
}

app.get("/copier/health", (req, res) => {
  res.json({
    ok: true,
    now: nowMs(),
    maxEventId: (copier.nextId || 1) - 1,
    eventsStored: copier.events.length,
    slaves: Object.keys(slaves.slaves || {}).length,
    clients: (clients.clients || []).length,
  });
});

// MASTER pushes OPEN/CLOSE
app.post("/copier/push", (req, res) => {
  if (!masterOk(req)) return res.status(401).json({ ok: false, error: "unauthorized master" });

  const b = req.body || {};
  const group = String(b.group || "");
  const type = String(b.type || "");
  if (!group || (type !== "OPEN" && type !== "CLOSE")) {
    return res.status(400).json({ ok: false, error: "bad group/type" });
  }

  const ev = {
    id: copier.nextId++,
    group,
    type,
    ts: nowMs(),
    master_ticket: Number(b.master_ticket || 0),
    open_time: Number(b.open_time || 0),
    symbol: String(b.symbol || ""),
    cmd: Number(b.cmd || 0),
    lots: Number(b.lots || b.lot || 0),
    price: Number(b.price || 0),
    sl: Number(b.sl || 0),
    tp: Number(b.tp || 0),
    magic: Number(b.magic || 0),
  };

  if (!ev.master_ticket || !ev.symbol) {
    return res.status(400).json({ ok: false, error: "missing master_ticket/symbol" });
  }

  copier.events.push(ev);
  saveCopier();
  res.json({ ok: true, id: ev.id });
});

// Slave registers (bind slaveId to client => 1 account per client)
app.post("/copier/registerSlave", (req, res) => {
  const b = req.body || {};
  const group = String(b.group || "");
  const slaveId = String(b.slaveId || "");
  if (!group || !slaveId) return res.status(400).json({ ok: false, error: "missing group/slaveId" });

  const c = requireClient(req, res, group);
  if (!c) return;

  if (!c.boundSlaveId) {
    c.boundSlaveId = slaveId;
    saveClients();
  } else if (c.boundSlaveId !== slaveId) {
    return res.status(403).json({ ok: false, error: "this api key is already bound to another slaveId" });
  }

  const k = slaveKey(group, slaveId);
  if (!slaves.slaves[k]) slaves.slaves[k] = { lastAckId: 0, lastSeenAt: 0 };
  slaves.slaves[k].lastSeenAt = nowMs();
  saveSlaves();

  res.json({ ok: true, boundSlaveId: c.boundSlaveId });
});

// Slave polls events
app.get("/copier/events", (req, res) => {
  const group = String(req.query.group || "");
  const slaveId = String(req.query.slaveId || "");
  const since = Number(req.query.since || 0);
  const limit = Math.min(500, Math.max(1, Number(req.query.limit || 200)));

  if (!group || !slaveId) return res.status(400).json({ ok: false, error: "missing group/slaveId" });

  const c = requireClient(req, res, group);
  if (!c) return;

  // enforce boundSlaveId
  if (!c.boundSlaveId) {
    c.boundSlaveId = slaveId;
    saveClients();
  } else if (c.boundSlaveId !== slaveId) {
    return res.status(403).json({ ok: false, error: "boundSlaveId mismatch (1 account per client)" });
  }

  const k = slaveKey(group, slaveId);
  if (!slaves.slaves[k]) slaves.slaves[k] = { lastAckId: 0, lastSeenAt: 0 };
  slaves.slaves[k].lastSeenAt = nowMs();
  saveSlaves();

  const out = [];
  for (let i = 0; i < copier.events.length; i++) {
    const ev = copier.events[i];
    if (ev.group !== group) continue;
    if (ev.id <= since) continue;
    out.push(ev);
    if (out.length >= limit) break;
  }

  res.json({ ok: true, now: nowMs(), events: out });
});

// Slave ACK
app.post("/copier/ack", (req, res) => {
  const b = req.body || {};
  const group = String(b.group || "");
  const slaveId = String(b.slaveId || "");
  const event_id = Number(b.event_id || 0);
  const status = String(b.status || "");
  if (!group || !slaveId || !event_id || !status) {
    return res.status(400).json({ ok: false, error: "missing fields" });
  }

  const c = requireClient(req, res, group);
  if (!c) return;

  if (c.boundSlaveId && c.boundSlaveId !== slaveId) {
    return res.status(403).json({ ok: false, error: "boundSlaveId mismatch" });
  }

  const k = slaveKey(group, slaveId);
  if (!slaves.slaves[k]) slaves.slaves[k] = { lastAckId: 0, lastSeenAt: 0 };
  slaves.slaves[k].lastAckId = Math.max(Number(slaves.slaves[k].lastAckId || 0), event_id);
  slaves.slaves[k].lastSeenAt = nowMs();
  saveSlaves();

  res.json({ ok: true });
});

// ================= Admin endpoints =================
app.get("/admin/clients", (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: "unauthorized admin" });
  res.json({ ok: true, now: nowMs(), clients: clients.clients || [] });
});

app.post("/admin/clients/add", (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: "unauthorized admin" });

  const b = req.body || {};
  const fullName = String(b.fullName || "").trim();
  const groupId = String(b.groupId || "").trim();
  const duration = String(b.duration || "M1").trim();

  if (!fullName || !groupId) return res.status(400).json({ ok: false, error: "missing fullName/groupId" });

  const clientId = crypto.randomBytes(6).toString("hex"); // 12 chars
  const apiKey = randKey(24); // 48 bytes hex => long enough

  const createdAt = nowMs();
  const expiresAt = createdAt + addDurationMs(duration);

  const c = {
    clientId,
    fullName,
    groupId,
    apiKey,
    enabled: true,
    createdAt,
    expiresAt,
    boundSlaveId: "",
  };

  clients.clients = clients.clients || [];
  clients.clients.push(c);
  saveClients();

  res.json({ ok: true, client: c });
});

app.post("/admin/clients/disable", (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: "unauthorized admin" });

  const b = req.body || {};
  const clientId = String(b.clientId || "");
  const enabled = Boolean(b.enabled);

  const c = findClientById(clientId);
  if (!c) return res.status(404).json({ ok: false, error: "not found" });

  c.enabled = enabled;
  saveClients();
  res.json({ ok: true });
});

app.post("/admin/clients/extend", (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: "unauthorized admin" });

  const b = req.body || {};
  const clientId = String(b.clientId || "");
  const duration = String(b.duration || "M1");

  const c = findClientById(clientId);
  if (!c) return res.status(404).json({ ok: false, error: "not found" });

  const base = Math.max(nowMs(), Number(c.expiresAt || 0));
  c.expiresAt = base + addDurationMs(duration);
  saveClients();
  res.json({ ok: true, expiresAt: c.expiresAt });
});

app.post("/admin/clients/resetBind", (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: "unauthorized admin" });

  const b = req.body || {};
  const clientId = String(b.clientId || "");

  const c = findClientById(clientId);
  if (!c) return res.status(404).json({ ok: false, error: "not found" });

  c.boundSlaveId = "";
  saveClients();
  res.json({ ok: true });
});

app.post("/admin/clients/delete", (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ ok: false, error: "unauthorized admin" });

  const b = req.body || {};
  const clientId = String(b.clientId || "");
  clients.clients = (clients.clients || []).filter(x => x.clientId !== clientId);
  saveClients();
  res.json({ ok: true });
});

// ================= Start =================
app.listen(PORT, () => console.log("Server listening on", PORT));
