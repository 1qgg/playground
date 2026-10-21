const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_EVENTS = Math.max(1, Number(process.env.MAX_CALLBACK_EVENTS || 500));
const CONFIG_FILE = path.join(__dirname, "data", "callback-config.json");
const API_BASE_URL = String(process.env.API_BASE_URL || "https://api.1q.gg").replace(/\/+$/, "");
const events = [];
const wallets = new Map();
const idempotency = new Map();
const callbackNonces = new Map();
let callbackConfigs = new Map();
try {
  const saved = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
  for (const [key, value] of Object.entries(saved)) if (value && typeof value.secret === "string") callbackConfigs.set(key, value.secret);
} catch {}

app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);
app.use(express.json({ limit: "1mb", verify: (req, res, buf) => { req.rawBody = Buffer.from(buf); } }));
app.use(express.static(path.join(__dirname, "public")));

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(k => [k, sortDeep(value[k])]));
  return value;
}
function canonicalJson(value) { return JSON.stringify(sortDeep(value)); }
function safeHeaders(headers) {
  const blocked = new Set(["authorization", "cookie", "set-cookie", "x-1q-signature"]);
  return Object.fromEntries(Object.entries(headers).filter(([k]) => !blocked.has(k.toLowerCase())));
}
function operatorFrom(req) { return String(req.get("X-Operator-Key") || req.get("X-1Q-Key") || "").trim(); }
function addEvent(req, operatorKey, { status, operation, player, currency, amount, balanceBefore, balanceAfter, responseCode, body, response } = {}) {
  const event = { id: crypto.randomUUID(), receivedAt: new Date().toISOString(), method: req.method, path: req.path,
    headers: safeHeaders(req.headers), operation: operation || "UNKNOWN", player: player || null, currency: currency || null,
    amount: amount ?? null, balanceBefore: balanceBefore ?? null, balanceAfter: balanceAfter ?? null,
    status: status || "received", responseCode: responseCode || null, body: body ?? req.body ?? null, response: response ?? null };
  events.unshift({ operatorKey, ...event });
  let count = 0;
  for (let i = events.length - 1; i >= 0; i--) {
    if (events[i].operatorKey === operatorKey && ++count > MAX_EVENTS) events.splice(i, 1);
  }
  return event;
}
function parseAmount(value) {
  const s = String(value ?? "");
  if (!/^(0|[1-9]\d*)(?:\.\d{1,4})?$/.test(s)) return null;
  const [whole, frac = ""] = s.split(".");
  return BigInt(whole) * 10000n + BigInt((frac + "0000").slice(0, 4));
}
function formatAmount(units) {
  const negative = units < 0n, n = negative ? -units : units;
  return (negative ? "-" : "") + (n / 10000n).toString() + "." + (n % 10000n).toString().padStart(4, "0");
}
function walletKey(operatorKey, user, currency) { return operatorKey + ":" + String(currency).toUpperCase() + ":" + String(user); }
function getBalance(operatorKey, user, currency) {
  const key = walletKey(operatorKey, user, currency);
  if (!wallets.has(key)) {
    const initial = parseAmount(process.env.CALLBACK_DEFAULT_BALANCE || "100.0000");
    wallets.set(key, initial === null ? 1000000n : initial);
  }
  return wallets.get(key);
}
function errorResponse(req, res, operatorKey, status, code, message, body = req.body) {
  const event = addEvent(req, operatorKey, { status: "rejected", operation: body?.type || body?.transaction?.type || "", player: body?.user_code,
    currency: body?.currency || body?.transaction?.currency || body?.slot?.currency, responseCode: code, body });
  const response = { accepted: false, status: "rejected", error_code: code, message };
  event.response = response;
  return res.status(status).json(response);
}
function persistCallbackConfigs() {
  fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
  const object = Object.fromEntries([...callbackConfigs].map(([key, secret]) => [key, { secret, updatedAt: new Date().toISOString() }]));
  const temp = CONFIG_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(object), { mode: 0o600 });
  fs.renameSync(temp, CONFIG_FILE);
}
function verifyCallback(req, operatorKey) {
  const secret = callbackConfigs.get(operatorKey);
  if (!secret) return { ok: false, status: 503, code: "CALLBACK_NOT_CONFIGURED", message: "Callback não configurado para esta Operator Key." };
  const timestamp = String(req.get("X-1Q-Timestamp") || "");
  const nonce = String(req.get("X-1Q-Nonce") || "");
  const idem = String(req.get("X-1Q-Idempotency-Key") || "");
  const signature = String(req.get("X-1Q-Signature") || "");
  if (!/^\d{10,13}$/.test(timestamp) || !nonce || nonce.length > 128 || !idem || idem.length > 128 || !/^[a-f0-9]{64}$/i.test(signature))
    return { ok: false, status: 401, code: "INVALID_CALLBACK_HEADERS", message: "Cabeçalhos de assinatura ou idempotência ausentes/inválidos." };
  const seconds = Number(timestamp.length > 10 ? Math.floor(Number(timestamp) / 1000) : Number(timestamp));
  if (!Number.isFinite(seconds) || Math.abs(Math.floor(Date.now() / 1000) - seconds) > 300)
    return { ok: false, status: 401, code: "CALLBACK_TIMESTAMP_EXPIRED", message: "Timestamp do callback fora da janela de 5 minutos." };
  const canonical = ["POST", req.path, timestamp, nonce, idem, crypto.createHash("sha256").update(canonicalJson(req.body || {})).digest("hex")].join("\n");
  const expected = crypto.createHmac("sha256", secret).update(canonical).digest("hex");
  const a = Buffer.from(expected, "hex"), b = Buffer.from(signature.toLowerCase(), "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
    return { ok: false, status: 401, code: "INVALID_CALLBACK_SIGNATURE", message: "Assinatura HMAC do callback inválida." };
  const now = Date.now();
  for (const [seen, expires] of callbackNonces) if (expires <= now) callbackNonces.delete(seen);
  const nonceKey = operatorKey + ":" + nonce;
  if (callbackNonces.has(nonceKey)) return { ok: false, status: 409, code: "CALLBACK_NONCE_REPLAY", message: "Nonce já utilizado; cada tentativa precisa de uma assinatura nova." };
  callbackNonces.set(nonceKey, now + 300000);
  return { ok: true, nonce, idem };
}
app.get("/health", (req, res) => res.json({ ok: true, service: "game-playground" }));
app.get("/api/callbacks", (req, res) => {
  const key = operatorFrom(req);
  if (!key) return res.status(400).json({ error: "Informe X-Operator-Key." });
  const own = events.filter(e => e.operatorKey === key);
  res.json({ data: own.map(({ operatorKey, ...e }) => e), configured: callbackConfigs.has(key), endpoint: "/callbacks/1q",
    wallets: [...wallets.keys()].filter(k => k.startsWith(key + ":")).length });
});
app.post("/api/callback-config", (req, res) => {
  const origin = req.get("Origin");
  if (origin) {
    try { if (new URL(origin).host !== req.get("host")) return res.status(403).json({ error: "Origem da solicitação inválida." }); }
    catch { return res.status(403).json({ error: "Origem da solicitação inválida." }); }
  }
  const operatorKey = String(req.body?.operatorKey || "").trim();
  const secret = String(req.body?.secret || "");
  const currentSecret = String(req.body?.currentSecret || "");
  if (!operatorKey || operatorKey.length > 256) return res.status(422).json({ error: "Operator Key inválida." });
  if (secret.length < 16 || secret.length > 4096) return res.status(422).json({ error: "O Callback Secret precisa ter entre 16 e 4096 caracteres." });
  if (callbackConfigs.has(operatorKey) && currentSecret !== callbackConfigs.get(operatorKey))
    return res.status(403).json({ error: "O Callback Secret já está configurado para esta Operator Key." });
  try {
    callbackConfigs.set(operatorKey, secret);
    persistCallbackConfigs();
    return res.json({ ok: true, configured: true });
  } catch {
    callbackConfigs.delete(operatorKey);
    return res.status(500).json({ error: "Não foi possível salvar a configuração do callback." });
  }
});
app.delete("/api/callbacks", (req, res) => {
  const key = operatorFrom(req);
  if (!key) return res.status(400).json({ error: "Informe X-Operator-Key." });
  for (let i = events.length - 1; i >= 0; i--) if (events[i].operatorKey === key) events.splice(i, 1);
  res.json({ ok: true });
});
app.post("/callbacks/1q", (req, res) => {
  const operatorKey = String(req.get("X-1Q-Key") || "").trim();
  if (!operatorKey) return errorResponse(req, res, "unknown", 401, "MISSING_OPERATOR_KEY", "Cabeçalho X-1Q-Key ausente.");
  const verified = verifyCallback(req, operatorKey);
  if (!verified.ok) return errorResponse(req, res, operatorKey, verified.status, verified.code, verified.message);
  const payload = req.body || {};
  const rawType = String(payload.type || payload.transaction?.type || "").toUpperCase().replace(/[\s_-]/g, "");
  const type = rawType === "WINBET" ? "WINBET" : rawType;
  const user = String(payload.user_code || "");
  const transaction = payload.transaction && typeof payload.transaction === "object" ? payload.transaction : {};
  const slot = payload.slot && typeof payload.slot === "object" ? payload.slot : {};
  const currency = String(payload.currency || transaction.currency || slot.currency || "").toUpperCase();
  if (!user || !/^[A-Z]{3}$/.test(currency)) return errorResponse(req, res, operatorKey, 422, "INVALID_CALLBACK_PAYLOAD", "user_code e currency ISO de 3 letras são obrigatórios.");
  const idemKey = operatorKey + ":" + verified.idem;
  const payloadHash = crypto.createHash("sha256").update(canonicalJson(payload)).digest("hex");
  const previous = idempotency.get(idemKey);
  if (previous) {
    if (previous.payloadHash !== payloadHash) return errorResponse(req, res, operatorKey, 409, "IDEMPOTENCY_CONFLICT", "A mesma chave de idempotência foi reutilizada com outro payload.");
    const event = addEvent(req, operatorKey, { status: "replayed", operation: type, player: user, currency, responseCode: "IDEMPOTENT_REPLAY", body: payload, response: previous.response });
    return res.status(200).json(previous.response);
  }
  const key = walletKey(operatorKey, user, currency);
  const before = getBalance(operatorKey, user, currency);
  let after = before, amount = null, response;
  if (type === "BALANCE") response = { status: "success", balance: formatAmount(before), currency };
  else if (type === "WINBET") {
    const bet = parseAmount(slot.bet), win = parseAmount(slot.win);
    if (bet === null || win === null || bet <= 0n) return errorResponse(req, res, operatorKey, 422, "INVALID_WINBET_AMOUNT", "slot.bet e slot.win precisam ser valores decimais não negativos e bet maior que zero.");
    amount = { bet: formatAmount(bet), win: formatAmount(win) };
    if (before < bet) return errorResponse(req, res, operatorKey, 422, "INSUFFICIENT_FUNDS", "Saldo insuficiente para a aposta.");
    after = before - bet + win;
    response = { accepted: true, status: "applied", operator_transaction_id: String(slot.txn_id || verified.idem), balance_before: formatAmount(before), balance_after: formatAmount(after), currency };
  } else if (["BET", "WIN", "REFUND"].includes(type)) {
    const units = parseAmount(transaction.amount);
    if (units === null || units <= 0n) return errorResponse(req, res, operatorKey, 422, "INVALID_TRANSACTION_AMOUNT", "transaction.amount precisa ser um decimal positivo.");
    amount = formatAmount(units);
    if (type === "BET") { if (before < units) return errorResponse(req, res, operatorKey, 422, "INSUFFICIENT_FUNDS", "Saldo insuficiente para a aposta."); after = before - units; }
    else after = before + units;
    response = { accepted: true, status: "applied", operator_transaction_id: String(transaction.id || verified.idem), balance_before: formatAmount(before), balance_after: formatAmount(after), currency };
  } else return errorResponse(req, res, operatorKey, 422, "UNSUPPORTED_CALLBACK_TYPE", "Operação não suportada pelo callback financeiro da 1Q.");
  if (type !== "BALANCE") wallets.set(key, after);
  idempotency.set(idemKey, { payloadHash, response });
  const event = addEvent(req, operatorKey, { status: "processed", operation: type, player: user, currency, amount, balanceBefore: formatAmount(before), balanceAfter: formatAmount(after), responseCode: "200", body: payload, response });
  return res.status(200).json(response);
});
app.post("/api/proxy", async (req, res) => {
  const { operatorKey, operatorSecret, method, apiPath, payload } = req.body || {};
  if (!operatorKey || !operatorSecret || !method || !apiPath) return res.status(400).json({ error: "Operator Key, Operator Secret, method e apiPath são obrigatórios." });
  let target;
  try {
    const base = new URL(API_BASE_URL);
    if (base.protocol !== "https:" && process.env.NODE_ENV === "production") throw new Error("API_BASE_URL deve usar HTTPS.");
    target = new URL(String(apiPath), base.href + "/");
    if (target.origin !== base.origin || target.username || target.password) throw new Error("Destino inválido.");
    if (!target.pathname.startsWith("/api/v1/")) throw new Error("Somente endpoints /api/v1/ são permitidos.");
  } catch (e) { return res.status(400).json({ error: "Caminho da API inválido: " + e.message }); }
  const verb = String(method).toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(verb)) return res.status(405).json({ error: "Método HTTP não permitido." });
  const bodyText = ["GET", "HEAD"].includes(verb) ? "" : JSON.stringify(payload ?? {});
  const timestamp = String(Math.floor(Date.now() / 1000)), nonce = crypto.randomUUID().replaceAll("-", "");
  const canonical = [verb, target.pathname, timestamp, nonce, crypto.createHash("sha256").update(bodyText).digest("hex")].join("\n");
  const signature = crypto.createHmac("sha256", operatorSecret).update(canonical).digest("hex");
  const headers = { Accept: "application/json", "X-Operator-Key": operatorKey, "X-1Q-Timestamp": timestamp, "X-1Q-Nonce": nonce, "X-1Q-Signature": signature };
  const isLaunch = verb === "POST" && target.pathname.replace(/\/+$/, "") === "/api/v1/launches";
  const idempotencyKey = isLaunch ? (String(req.body?.idempotencyKey || "").trim() || crypto.randomUUID()) : "";
  if (isLaunch) headers["Idempotency-Key"] = idempotencyKey;
  if (bodyText) headers["Content-Type"] = "application/json";
  try {
    const upstream = await fetch(target, { method: verb, headers, body: bodyText || undefined, redirect: "error", signal: AbortSignal.timeout(30000) });
    const raw = await upstream.text(); let data;
    try { data = JSON.parse(raw); } catch { data = raw; }
    res.status(200).json({ upstreamStatus: upstream.status, ...(isLaunch ? { idempotencyKey } : {}), data });
  } catch (e) { res.status(502).json({ error: "Falha na chamada à API", detail: e.message }); }
});
app.listen(PORT, "0.0.0.0", () => console.log("Game Playground listening on port " + PORT));
