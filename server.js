import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import compression from "compression";
import QRCode from "qrcode";
import pg from "pg";
import { v4 as uuidv4 } from "uuid";

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";

if (process.env.NODE_ENV === "production" && (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32)) {
  throw new Error("JWT_SECRET must be set to a random secret of at least 32 characters in production.");
}
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 10
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const schema = `
CREATE TABLE IF NOT EXISTS admins (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nodes (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 443,
  protocol TEXT NOT NULL DEFAULT 'vless',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS clients (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  uuid TEXT UNIQUE NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'vless',
  node_id INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
  server TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 443,
  traffic_gb NUMERIC(12,2) NOT NULL DEFAULT 50,
  used_gb NUMERIC(12,2) NOT NULL DEFAULT 0,
  device_limit INTEGER NOT NULL DEFAULT 1,
  expires_at TIMESTAMPTZ NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`;

async function initDb() {
  await pool.query(schema);
  const exists = await pool.query("SELECT id FROM admins WHERE username=$1", [process.env.ADMIN_USERNAME || "admin"]);
  if (!exists.rowCount) {
    const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(18).toString("base64url");
    const hash = await bcrypt.hash(password, 12);
    await pool.query("INSERT INTO admins(username,password_hash) VALUES($1,$2)", [
      process.env.ADMIN_USERNAME || "admin", hash
    ]);
    console.log(`Initial admin created: ${process.env.ADMIN_USERNAME || "admin"}`);
    if (!process.env.ADMIN_PASSWORD) console.log(`Generated password: ${password}`);
  }
}

function signAdmin(admin) {
  return jwt.sign({ sub: admin.id, username: admin.username, role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
}
function requireAuth(req, res, next) {
  const token = req.cookies.rxt_token || (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "احراز هویت لازم است" });
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: "نشست منقضی شده است" }); }
}
function cleanProtocol(p) {
  const value = String(p || "vless").toLowerCase();
  const allowed = ["vless","vmess","trojan","shadowsocks","wireguard"];
  if (!allowed.includes(value)) throw new Error("Protocol is not supported");
  return value;
}
function enc(v) { return encodeURIComponent(String(v)); }

function generateConfig(c) {
  const protocol = cleanProtocol(c.protocol);
  const server = c.server || "example.com";
  const port = Number(c.port || 443);
  const id = c.uuid || uuidv4();
  const name = c.name || `RXT-${c.username || "client"}`;

  if (protocol === "vless") {
    const q = new URLSearchParams({ encryption: "none", security: "tls", type: "tcp" });
    return `vless://${id}@${server}:${port}?${q.toString()}#${enc(name)}`;
  }
  if (protocol === "vmess") {
    const payload = {
      v: "2", ps: name, add: server, port: String(port), id,
      aid: "0", scy: "auto", net: "tcp", type: "none",
      host: "", path: "", tls: "tls"
    };
    return `vmess://${Buffer.from(JSON.stringify(payload)).toString("base64")}`;
  }
  if (protocol === "trojan") {
    const password = c.password || id;
    return `trojan://${enc(password)}@${server}:${port}?security=tls&type=tcp#${enc(name)}`;
  }
  if (protocol === "shadowsocks") {
    const method = c.method || "aes-256-gcm";
    const password = c.password || crypto.randomBytes(16).toString("base64url");
    return `ss://${Buffer.from(`${method}:${password}`).toString("base64url")}@${server}:${port}#${enc(name)}`;
  }
  const privateKey = c.privateKey || "<CLIENT_PRIVATE_KEY>";
  const publicKey = c.publicKey || "<SERVER_PUBLIC_KEY>";
  return `[Interface]
PrivateKey = ${privateKey}
Address = ${c.address || "10.0.0.2/32"}
DNS = ${c.dns || "1.1.1.1"}

[Peer]
PublicKey = ${publicKey}
Endpoint = ${server}:${port}
AllowedIPs = ${c.allowedIPs || "0.0.0.0/0, ::/0"}
PersistentKeepalive = 25`;
}

function subscriptionFor(client) {
  const config = generateConfig(client);
  return Buffer.from(config, "utf8").toString("base64");
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "RXT Config Panel" });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  const result = await pool.query("SELECT * FROM admins WHERE username=$1", [username || ""]);
  if (!result.rowCount || !(await bcrypt.compare(password || "", result.rows[0].password_hash))) {
    return res.status(401).json({ error: "نام کاربری یا رمز عبور نادرست است" });
  }
  const token = signAdmin(result.rows[0]);
  res.cookie("rxt_token", token, {
    httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production",
    maxAge: 12 * 60 * 60 * 1000
  });
  res.json({ ok: true });
});
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("rxt_token");
  res.json({ ok: true });
});

app.get("/api/stats", requireAuth, async (_req, res) => {
  const [users, active, nodes, traffic] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM clients"),
    pool.query("SELECT COUNT(*)::int AS count FROM clients WHERE enabled=true AND expires_at > NOW()"),
    pool.query("SELECT COUNT(*)::int AS count FROM nodes WHERE enabled=true"),
    pool.query("SELECT COALESCE(SUM(traffic_gb),0) AS total, COALESCE(SUM(used_gb),0) AS used FROM clients")
  ]);
  res.json({ users: users.rows[0].count, active: active.rows[0].count, nodes: nodes.rows[0].count, traffic: traffic.rows[0] });
});

app.get("/api/nodes", requireAuth, async (_req, res) => {
  res.json((await pool.query("SELECT * FROM nodes ORDER BY id DESC")).rows);
});
app.post("/api/nodes", requireAuth, async (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.address) return res.status(400).json({ error: "نام و آدرس Node الزامی است" });
  const r = await pool.query(
    "INSERT INTO nodes(name,address,port,protocol) VALUES($1,$2,$3,$4) RETURNING *",
    [b.name, b.address, Number(b.port || 443), cleanProtocol(b.protocol)]
  );
  res.status(201).json(r.rows[0]);
});
app.delete("/api/nodes/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM nodes WHERE id=$1", [req.params.id]);
  res.status(204).end();
});

app.get("/api/clients", requireAuth, async (_req, res) => {
  res.json((await pool.query(`
    SELECT c.*, n.name AS node_name
    FROM clients c LEFT JOIN nodes n ON n.id=c.node_id
    ORDER BY c.id DESC
  `)).rows);
});
app.post("/api/clients", requireAuth, async (req, res) => {
  const b = req.body || {};
  if (!b.username) return res.status(400).json({ error: "نام کاربری الزامی است" });
  const days = Math.max(1, Number(b.days || 30));
  const r = await pool.query(`
    INSERT INTO clients
    (username,uuid,protocol,node_id,server,port,traffic_gb,device_limit,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW()+($9 * INTERVAL '1 day'))
    RETURNING *
  `, [
    b.username, b.uuid || uuidv4(), cleanProtocol(b.protocol),
    b.node_id ? Number(b.node_id) : null, b.server || "example.com",
    Number(b.port || 443), Number(b.traffic_gb || 50),
    Number(b.device_limit || 1), days
  ]);
  res.status(201).json(r.rows[0]);
});
app.patch("/api/clients/:id/toggle", requireAuth, async (req, res) => {
  const r = await pool.query("UPDATE clients SET enabled=NOT enabled WHERE id=$1 RETURNING *", [req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: "کاربر پیدا نشد" });
  res.json(r.rows[0]);
});
app.delete("/api/clients/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM clients WHERE id=$1", [req.params.id]);
  res.status(204).end();
});

app.get("/api/clients/:id/config", requireAuth, async (req, res) => {
  const r = await pool.query("SELECT c.*, n.address AS node_address FROM clients c LEFT JOIN nodes n ON n.id=c.node_id WHERE c.id=$1", [req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: "کاربر پیدا نشد" });
  const c = r.rows[0];
  const config = generateConfig({ ...c, server: c.node_address || c.server });
  const qr = await QRCode.toDataURL(config, { width: 320, margin: 1 });
  res.json({ config, qr });
});

app.get("/sub/:token", async (req, res) => {
  try {
    const id = Buffer.from(req.params.token, "base64url").toString("utf8");
    const r = await pool.query("SELECT * FROM clients WHERE id=$1 AND enabled=true", [id]);
    if (!r.rowCount) return res.status(404).send("Subscription not found");
    const c = r.rows[0];
    if (new Date(c.expires_at) <= new Date()) return res.status(410).send("Subscription expired");
    res.type("text/plain").send(subscriptionFor(c));
  } catch { res.status(400).send("Invalid subscription"); }
});

app.get("/api/clients/:id/subscription", requireAuth, async (req, res) => {
  const r = await pool.query("SELECT id FROM clients WHERE id=$1", [req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: "کاربر پیدا نشد" });
  const token = Buffer.from(String(req.params.id)).toString("base64url");
  const base = process.env.BASE_URL || "";
  res.json({ token, url: `${base.replace(/\/$/, "")}/sub/${token}` });
});

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

initDb().then(() => app.listen(PORT, "0.0.0.0", () => console.log(`RXT listening on ${PORT}`)))
  .catch(err => { console.error(err); process.exit(1); });
