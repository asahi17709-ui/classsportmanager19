// CS Manager API v2 (Netlify Function v2 + Netlify Blobs) - hardened admin security
//   Public : GET /api/state (poll ~2.5 s, ETag)           Writes: PUT /api/state (token + role checked on the server)
//   Auth   : POST /api/login | /api/login2 | /api/register | /api/change-pin
//   Admin security: /api/2fa/confirm | /api/unlock | /api/recover | /api/lockdown | /api/signout-all | GET /api/security
//   Accounts: GET,POST /api/accounts
// PINs are only hashed here (PBKDF2-SHA256, 310k rounds, per-user salt). The admin additionally needs a rotating
// 6-digit code (TOTP, RFC 6238) generated on the admin's own device (Apple Passwords / any authenticator),
// so nothing secret is ever "sent" over a channel that can be intercepted.
import { getStore } from "@netlify/blobs";
import { pbkdf2, randomBytes, timingSafeEqual, createHmac } from "node:crypto";
import { promisify } from "node:util";

const pb = promisify(pbkdf2), ITER = 310000;
const SEED = { u: "aris211013", n: "Aris211013", role: "admin", st: "ok", tmp: true, s: "630cdfde42cb15468dbe7c1bc585e2f9", h: "993d9ec7bd455c0c5cbdd034635c495c1fb06531d246a7f1cd3fb58213704b4b", t: 0 };

const store = () => getStore({ name: "cs-manager", consistency: "strong" });
const J = (o, status = 200, h = {}) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...h } });
const hash = async (sec, salt) => (await pb(String(sec), Buffer.from(salt, "hex"), ITER, 32, "sha256")).toString("hex");
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const norm = (u) => String(u || "").trim().toLowerCase();
const okU = (u) => /^[a-z0-9\u0E00-\u0E7F_.-]{3,20}$/.test(u);
const ok6 = (v) => /^\d{6}$/.test(String(v));
const weak = (v) => /^(\d)\1{5}$/.test(v) || "0123456789".includes(v) || "9876543210".includes(v);
const bad = () => J({ error: "bad" }, 400);
const body = async (req) => { const t = await req.text(); if (t.length > 200000) return null; try { return JSON.parse(t); } catch { return null; } };
const salt = () => randomBytes(16).toString("hex");

// ---------- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----------
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const b32 = (buf) => { let bits = 0, v = 0, o = ""; for (const x of buf) { v = ((v << 8) | x) & 0xffffff; bits += 8; while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } v &= (1 << bits) - 1; } if (bits > 0) o += B32[(v << (5 - bits)) & 31]; return o; };
const unb32 = (s) => { let bits = 0, v = 0; const out = []; for (const c of String(s).replace(/=+$/, "")) { const i = B32.indexOf(c); if (i < 0) continue; v = ((v << 5) | i) & 0xffffff; bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; v &= (1 << bits) - 1; } } return Buffer.from(out); };
export const totp = (key, step) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(step)); const h = createHmac("sha1", unb32(key)).update(b).digest(), o = h[19] & 15; return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000).padStart(6, "0"); };
const checkTotp = (t, code, now = Date.now()) => { // returns the accepted step, or null. A step can be used once.
  if (!t || !t.k || !ok6(code)) return null;
  const cur = Math.floor(now / 30000);
  for (const d of [0, -1, 1]) { const s = cur + d; if (s > (t.ls || 0) && eq(totp(t.k, s), String(code))) return s; }
  return null;
};
const otpUri = (u, k) => `otpauth://totp/CS%20Manager:${encodeURIComponent(u)}?secret=${k}&issuer=CS%20Manager&algorithm=SHA1&digits=6&period=30`;
const startEnroll = (usr) => { const k = b32(randomBytes(20)); usr.pend2 = { k }; return { key: k, uri: otpUri(usr.u, k) }; };

// ---------- tokens ----------
async function getSecret(st) { let s = await st.get("secret"); if (!s) { s = randomBytes(32).toString("hex"); await st.set("secret", s); } return s; }
const sign = (secret, p) => { const b = Buffer.from(JSON.stringify(p)).toString("base64url"); return b + "." + createHmac("sha256", secret).update(b).digest("base64url"); };
function verify(secret, tok, kind) {
  if (typeof tok !== "string") return null;
  const [b, sg] = tok.split(".");
  if (!b || !sg || !eq(sg, createHmac("sha256", secret).update(b).digest("base64url"))) return null;
  let p; try { p = JSON.parse(Buffer.from(b, "base64url").toString()); } catch { return null; }
  return p && p.k === kind && p.exp > Date.now() ? p : null;
}
const session = (secret, usr, a, lim) => ({ token: sign(secret, { u: usr.u, role: usr.role, k: "s", sv: a.sec.sv, lim: !!lim, exp: Date.now() + (lim ? 15 * 60e3 : 8 * 3600e3) }), user: { u: usr.u, n: usr.n, role: usr.role } });
function who(req, secret, a, { allowLim = false } = {}) { // verifies the token, its session version, and that the account is still active
  const p = verify(secret, (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, ""), "s");
  if (!p || p.sv !== a.sec.sv || (p.lim && !allowLim)) return null;
  const usr = a.users.find((x) => x.u === p.u);
  return usr && usr.st === "ok" && !usr.locked ? usr : null;
}

// ---------- storage ----------
async function getAcc(st) {
  let a = await st.get("accounts", { type: "json" });
  if (!a) { a = { users: [{ ...SEED }], lock: {}, ulock: {}, sec: { sv: 1, lockdown: false } }; await st.setJSON("accounts", a); }
  a.lock = a.lock || {}; a.ulock = a.ulock || {}; a.sec = a.sec || { sv: 1, lockdown: false };
  return a;
}
const saveAcc = (st, a) => st.setJSON("accounts", a);
async function audit(st, ev, u, ctx, extra) {
  const l = (await st.get("audit", { type: "json" })) || [];
  l.push({ t: Date.now(), ev, u: u || "", ip: ctx && ctx.ip ? String(ctx.ip) : "", ...(extra || {}) });
  await st.setJSON("audit", l.slice(-200));
}
async function setStateFlags(st, flags) { const s = (await st.get("state", { type: "json" })) || { rev: 0, tmp: true }; Object.assign(s, flags); s.rev = (s.rev || 0) + 1; await st.setJSON("state", s); }
const backoff = (f) => (f >= 5 ? Math.min(900, 30 * 2 ** (f - 5)) : 0);
// Hammering an admin account (even while it is temporarily locked) counts. 10 tries in a row = hard lock + automatic lockdown.
async function hardLock(st, a, usr, ctx, why) {
  usr.locked = true; a.sec.lockdown = true;
  await saveAcc(st, a); await setStateFlags(st, { lockdown: true });
  await audit(st, "admin_hardlock", usr.u, ctx, { why });
  return J({ error: "adminlocked" }, 423);
}
async function lockedNow(st, a, u, usr, L, ctx) { // called when a temporary lock is active
  if (usr && usr.role === "admin") {
    L.f = (L.f || 0) + 1; a.lock[u] = L;
    if (L.f >= 10) return hardLock(st, a, usr, ctx, "hammering");
    await saveAcc(st, a);
  }
  return J({ error: "locked", retry: Math.ceil((L.until - Date.now()) / 1000) }, 429);
}

// ---------- shared state ----------
async function getState(st, req) {
  const s = (await st.get("state", { type: "json" })) || { rev: 0, tmp: true };
  const tag = `"${s.rev}-${s.tmp ? 1 : 0}-${s.lockdown ? 1 : 0}"`;
  if (req.headers.get("if-none-match") === tag) return new Response(null, { status: 304, headers: { etag: tag, "cache-control": "no-store" } });
  return J({ rev: s.rev, tmp: !!s.tmp, lockdown: !!s.lockdown, app: s.app ?? null, status: s.status ?? null, practice: s.practice ?? null }, 200, { etag: tag });
}
const isInt = (v, a, b) => Number.isInteger(v) && v >= a && v <= b;
const validApp = (a) => a && typeof a === "object" && JSON.stringify(a).length < 60000 && isInt(a.total, 1, 500) && Array.isArray(a.teams) && a.teams.length <= 20 &&
  a.teams.every((t) => t && typeof t.id === "string" && t.id.length <= 20 && typeof t.name === "string" && t.name.length >= 1 && t.name.length <= 30 && isInt(t.cap, 0, 500) && typeof t.h === "number" && Array.isArray(t.m) && t.m.length <= 500 && t.m.every((n) => isInt(n, 1, 500)));
const validPractice = (p) => Array.isArray(p) && p.length <= 300 && p.every((x) => x && isInt(x.d, 0, 6) && /^\d{2}:\d{2}$/.test(x.t) && typeof x.a === "string" && x.a.length <= 30 && String(x.note || "").length <= 80);
const validEntry = (v) => v && typeof v === "object" && String(v.note || "").length <= 120 && (v.s === undefined || v.s === "ok" || v.s === "slack");
const cleanEntry = (v) => ({ s: v.s || "slack", note: String(v.note || "").slice(0, 120), t: Number(v.t) || Date.now() });

async function putState(st, req, secret) {
  const a = await getAcc(st), usr = who(req, secret, a);
  if (!usr) return J({ error: "auth" }, 401);
  const role = usr.role, b = await body(req);
  if (!b || typeof b !== "object" || Array.isArray(b)) return bad();
  const keys = Object.keys(b);
  if (!keys.every((k) => ["app", "status", "practice", "statusPatch"].includes(k))) return bad();
  if (a.sec.lockdown && role !== "admin") return J({ error: "lockdown" }, 403);
  if (role === "member" && keys.some((k) => k !== "statusPatch")) return J({ error: "forbidden" }, 403);
  if (role !== "admin" && role !== "member") return J({ error: "forbidden" }, 403);
  const s = (await st.get("state", { type: "json" })) || { rev: 0, tmp: false };
  if ("app" in b) { if (!validApp(b.app)) return bad(); s.app = b.app; }
  if ("practice" in b) { if (!validPractice(b.practice)) return bad(); s.practice = b.practice; }
  if ("status" in b) {
    const o = b.status;
    if (!o || typeof o !== "object" || Array.isArray(o) || Object.keys(o).length > 500 || !Object.entries(o).every(([k, v]) => /^\d{1,3}$/.test(k) && validEntry(v))) return bad();
    s.status = Object.fromEntries(Object.entries(o).map(([k, v]) => [k, cleanEntry(v)]));
  }
  if ("statusPatch" in b) {
    const p = b.statusPatch;
    if (!p || typeof p !== "object" || Array.isArray(p) || Object.keys(p).length > 100) return bad();
    const cur = { ...(s.status || {}) };
    for (const [k, v] of Object.entries(p)) {
      if (!/^\d{1,3}$/.test(k)) return bad();
      if (v === null) delete cur[k]; else { if (!validEntry(v)) return bad(); cur[k] = cleanEntry(v); }
    }
    s.status = cur;
  }
  s.rev = (s.rev || 0) + 1;
  await st.setJSON("state", s);
  return J({ rev: s.rev });
}

// ---------- login ----------
// One failure path for PIN and code failures. Admin: 10 failures in a row = HARD LOCK + automatic lockdown.
async function failure(st, a, u, usr, ctx, why) {
  const L = a.lock[u] || { f: 0, until: 0 }, f = (L.f || 0) + 1, wait = backoff(f);
  a.lock[u] = { f, until: wait ? Date.now() + wait * 1000 : 0 };
  if (Object.keys(a.lock).length > 500) a.lock = {};
  let res;
  if (usr && usr.role === "admin" && f >= 10 && !usr.locked) return hardLock(st, a, usr, ctx, why);
  await saveAcc(st, a);
  if (usr && usr.role === "admin") await audit(st, "admin_fail", u, ctx, { why, f });
  res = wait ? J({ error: "locked", retry: wait }, 429) : J({ error: why === "code" ? "code" : "bad" }, 401);
  return res;
}
async function login(st, req, secret, ctx) {
  const b = await body(req), u = norm(b && b.u), sec = String((b && b.secret) ?? "");
  if (!u || !sec || sec.length > 64) return J({ error: "bad" }, 401);
  const a = await getAcc(st), usr = a.users.find((x) => x.u === u), L = a.lock[u] || { f: 0, until: 0 };
  if (usr && usr.locked) { await audit(st, "login_blocked_locked", u, ctx); return J({ error: "adminlocked" }, 423); }
  if (L.until > Date.now()) return lockedNow(st, a, u, usr, L, ctx);
  const h = await hash(sec, usr ? usr.s : "00".repeat(16)); // same work for unknown users
  if (!(usr && eq(h, usr.h))) return failure(st, a, u, usr, ctx, "pin");
  if (usr.st === "pending") return J({ error: "pending" }, 403);
  if (usr.st === "off") return J({ error: "off" }, 403);
  if (a.sec.lockdown && usr.role !== "admin") return J({ error: "lockdown" }, 403);
  if (usr.tmp || usr.rec) { if (a.lock[u]) { delete a.lock[u]; await saveAcc(st, a); } return J({ mustChange: true, ticket: sign(secret, { u, k: "chg", exp: Date.now() + 300000 }) }); }
  if (usr.role === "admin") {
    if (usr.totp) return J({ need2fa: true, ticket: sign(secret, { u, k: "2fa", exp: Date.now() + 300000 }) });
    const en = startEnroll(usr); await saveAcc(st, a); // PIN ok but 2FA never confirmed: enroll again
    return J({ ...session(secret, usr, a, true), enroll: en });
  }
  if (a.lock[u]) { delete a.lock[u]; await saveAcc(st, a); }
  await audit(st, "login_ok", u, ctx);
  return J(session(secret, usr, a));
}
async function login2(st, req, secret, ctx) {
  const b = await body(req); if (!b) return bad();
  const p = verify(secret, b.ticket, "2fa"); if (!p) return J({ error: "expired" }, 401);
  const a = await getAcc(st), usr = a.users.find((x) => x.u === p.u), L = a.lock[p.u] || { f: 0, until: 0 };
  if (!usr || usr.locked || !usr.totp) return J({ error: "adminlocked" }, 423);
  if (L.until > Date.now()) return lockedNow(st, a, usr.u, usr, L, ctx);
  const step = checkTotp(usr.totp, b.code);
  if (!step) return failure(st, a, usr.u, usr, ctx, "code");
  usr.totp.ls = step; delete a.lock[usr.u]; await saveAcc(st, a); await audit(st, "admin_login_ok", usr.u, ctx);
  return J(session(secret, usr, a));
}
async function register(st, req, ctx) {
  const b = await body(req); if (!b) return bad();
  const u = norm(b.u), n = String(b.n || "").trim().slice(0, 30) || u, pin = String(b.pin || "");
  if (!okU(u) || !ok6(pin)) return bad();
  if (weak(pin)) return J({ error: "weak" }, 400);
  const a = await getAcc(st);
  if (a.sec.lockdown) return J({ error: "lockdown" }, 403);
  if (a.users.length >= 300 || a.users.filter((x) => x.st === "pending").length >= 100) return J({ error: "full" }, 429);
  if (a.users.some((x) => x.u === u)) return J({ error: "taken" }, 409);
  const s = salt();
  a.users.push({ u, n, role: "member", st: "pending", s, h: await hash(pin, s), t: Date.now() });
  await saveAcc(st, a); await audit(st, "register", u, ctx);
  return J({ ok: true });
}

// ---------- PIN / 2FA / recovery ----------
async function changePin(st, req, secret, ctx) {
  const b = await body(req); if (!b) return bad();
  const pin = String(b.pin || ""); if (!ok6(pin)) return bad();
  if (weak(pin)) return J({ error: "weak" }, 400);
  const a = await getAcc(st);
  if (b.ticket) { // first setup (temporary password) or recovery with the recovery key
    const p = verify(secret, b.ticket, "chg"); if (!p) return J({ error: "auth" }, 401);
    const usr = a.users.find((x) => x.u === p.u);
    if (!usr || usr.st !== "ok" || !(usr.tmp || usr.rec)) return J({ error: "auth" }, 401);
    const wasTmp = !!usr.tmp;
    if (typeof b.name === "string" && b.name.trim()) usr.n = b.name.trim().slice(0, 30);
    usr.s = salt(); usr.h = await hash(pin, usr.s); delete usr.tmp; delete usr.rec;
    delete a.lock[usr.u];
    if (usr.role === "admin") {
      usr.totp = null; delete usr.rk; delete usr.locked; a.sec.sv++; // revoke every old session
      const en = startEnroll(usr); await saveAcc(st, a);
      if (wasTmp) await setStateFlags(st, { tmp: a.users.some((x) => x.tmp) });
      await audit(st, wasTmp ? "admin_setup_pin" : "admin_recovered", usr.u, ctx);
      return J({ ...session(secret, usr, a, true), enroll: en });
    }
    await saveAcc(st, a);
    if (wasTmp) await setStateFlags(st, { tmp: a.users.some((x) => x.tmp) });
    return J(session(secret, usr, a));
  }
  const usr = who(req, secret, a); if (!usr) return J({ error: "auth" }, 401);
  if (usr.role === "admin") { const step = checkTotp(usr.totp, b.code); if (!step) return J({ error: "code" }, 401); usr.totp.ls = step; }
  usr.s = salt(); usr.h = await hash(pin, usr.s);
  await saveAcc(st, a); await audit(st, "pin_change", usr.u, ctx);
  return J({ ok: true });
}
async function confirm2fa(st, req, secret, ctx) {
  const b = await body(req); if (!b) return bad();
  const a = await getAcc(st), usr = who(req, secret, a, { allowLim: true });
  if (!usr || usr.role !== "admin" || !usr.pend2) return J({ error: "auth" }, 401);
  const step = checkTotp({ k: usr.pend2.k, ls: 0 }, b.code);
  if (!step) return J({ error: "code" }, 401);
  usr.totp = { k: usr.pend2.k, ls: step }; delete usr.pend2;
  const raw = b32(randomBytes(20)), rs = salt();
  usr.rk = { s: rs, h: await hash(raw, rs) };
  await saveAcc(st, a); await audit(st, "admin_2fa_enrolled", usr.u, ctx);
  return J({ ...session(secret, usr, a), recovery: raw.match(/.{1,4}/g).join("-") });
}
async function ulockFail(st, a, u, ctx, why) {
  const L = a.ulock[u] || { f: 0, until: 0 }, f = (L.f || 0) + 1, wait = backoff(f);
  a.ulock[u] = { f, until: wait ? Date.now() + wait * 1000 : 0 };
  await saveAcc(st, a); await audit(st, why + "_fail", u, ctx, { f });
  return wait ? J({ error: "locked", retry: wait }, 429) : J({ error: "code" }, 401);
}
async function unlock(st, req, ctx) {
  const b = await body(req), u = norm(b && b.u); if (!u) return bad();
  const a = await getAcc(st), usr = a.users.find((x) => x.u === u), L = a.ulock[u] || { f: 0, until: 0 };
  if (L.until > Date.now()) return J({ error: "locked", retry: Math.ceil((L.until - Date.now()) / 1000) }, 429);
  if (!usr || usr.role !== "admin" || !usr.locked || !usr.totp) return J({ error: "code" }, 401);
  const step = checkTotp(usr.totp, b.code);
  if (!step) return ulockFail(st, a, u, ctx, "unlock");
  usr.totp.ls = step; delete usr.locked; delete a.lock[u]; delete a.ulock[u]; a.sec.sv++; // admin lock lifted; lockdown stays until the admin ends it
  await saveAcc(st, a); await audit(st, "admin_unlocked", u, ctx);
  return J({ ok: true });
}
async function recover(st, req, secret, ctx) {
  const b = await body(req), u = norm(b && b.u), key = String((b && b.key) || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  if (!u || key.length < 20) return J({ error: "code" }, 401);
  const a = await getAcc(st), usr = a.users.find((x) => x.u === u), L = a.ulock[u] || { f: 0, until: 0 };
  if (L.until > Date.now()) return J({ error: "locked", retry: Math.ceil((L.until - Date.now()) / 1000) }, 429);
  const h = await hash(key, usr && usr.rk ? usr.rk.s : "00".repeat(16));
  if (!(usr && usr.role === "admin" && usr.rk && eq(h, usr.rk.h))) return ulockFail(st, a, u, ctx, "recover");
  usr.rec = true; delete a.ulock[u]; await saveAcc(st, a); await audit(st, "recovery_key_used", u, ctx);
  return J({ mustChange: true, ticket: sign(secret, { u, k: "chg", exp: Date.now() + 300000 }) });
}

// ---------- trusted device for camera unlock (members only; the face match itself never leaves the device) ----------
// The browser holds a random device key. After the on-device face match it sends the key; the server checks its hash,
// rotates it on every use (a stolen copy is detected and the device is revoked), and never accepts admins.
async function deviceRegister(st, req, secret, ctx) {
  const a = await getAcc(st), usr = who(req, secret, a);
  if (!usr || usr.role !== "member") return J({ error: "forbidden" }, 403);
  a.devs = a.devs || {};
  const mine = Object.entries(a.devs).filter(([, d]) => d.u === usr.u).sort((x, y) => x[1].t - y[1].t);
  while (mine.length >= 3) delete a.devs[mine.shift()[0]];
  const id = randomBytes(9).toString("hex"), key = randomBytes(32).toString("hex"), s = salt();
  a.devs[id] = { u: usr.u, s, h: await hash(key, s), t: Date.now(), exp: Date.now() + 30 * 864e5 };
  await saveAcc(st, a); await audit(st, "device_register", usr.u, ctx);
  return J({ id, key });
}
async function deviceLogin(st, req, secret, ctx) {
  const b = await body(req); if (!b || typeof b.id !== "string" || typeof b.key !== "string") return bad();
  const a = await getAcc(st); a.devs = a.devs || {};
  const d = a.devs[b.id];
  if (!d || d.exp < Date.now()) return J({ error: "bad" }, 401);
  if (!eq(await hash(b.key, d.s), d.h)) { delete a.devs[b.id]; await saveAcc(st, a); await audit(st, "device_key_mismatch", d.u, ctx); return J({ error: "bad" }, 401); }
  const usr = a.users.find((x) => x.u === d.u);
  if (!usr || usr.st !== "ok" || usr.role !== "member") { delete a.devs[b.id]; await saveAcc(st, a); return J({ error: "bad" }, 401); }
  if (a.sec.lockdown) return J({ error: "lockdown" }, 403);
  const key = randomBytes(32).toString("hex"); d.s = salt(); d.h = await hash(key, d.s); d.exp = Date.now() + 30 * 864e5;
  await saveAcc(st, a); await audit(st, "device_login", usr.u, ctx);
  return J({ ...session(secret, usr, a), id: b.id, key });
}
async function deviceRemove(st, req, secret) {
  const b = await body(req), a = await getAcc(st), usr = who(req, secret, a);
  if (!usr || !b) return J({ error: "auth" }, 401);
  a.devs = a.devs || {};
  if (a.devs[b.id] && a.devs[b.id].u === usr.u) { delete a.devs[b.id]; await saveAcc(st, a); }
  return J({ ok: true });
}

// ---------- admin controls (need a fresh code) ----------
async function adminCode(st, req, secret, a, code) {
  const usr = who(req, secret, a);
  if (!usr || usr.role !== "admin") return { err: J({ error: "forbidden" }, 403) };
  const step = checkTotp(usr.totp, code);
  if (!step) return { err: J({ error: "code" }, 401) };
  usr.totp.ls = step; return { usr };
}
async function lockdown(st, req, secret, ctx) {
  const b = await body(req); if (!b) return bad();
  const a = await getAcc(st), r = await adminCode(st, req, secret, a, b.code); if (r.err) return r.err;
  a.sec.lockdown = !!b.on; if (b.on) { a.sec.sv++; a.devs = {}; } // everyone is signed out and every trusted device is revoked; the admin gets a fresh session below
  await saveAcc(st, a); await setStateFlags(st, { lockdown: !!b.on }); await audit(st, b.on ? "lockdown_on" : "lockdown_off", r.usr.u, ctx);
  return J({ ok: true, lockdown: !!b.on, ...session(secret, r.usr, a) });
}
async function signoutAll(st, req, secret, ctx) {
  const b = await body(req); if (!b) return bad();
  const a = await getAcc(st), r = await adminCode(st, req, secret, a, b.code); if (r.err) return r.err;
  a.sec.sv++; a.devs = {}; await saveAcc(st, a); await audit(st, "signout_all", r.usr.u, ctx);
  return J({ ok: true, ...session(secret, r.usr, a) });
}
async function security(st, req, secret) {
  const a = await getAcc(st), usr = who(req, secret, a);
  if (!usr || usr.role !== "admin") return J({ error: "forbidden" }, 403);
  const l = ((await st.get("audit", { type: "json" })) || []).slice(-30).reverse();
  return J({ lockdown: !!a.sec.lockdown, twofa: !!usr.totp, audit: l });
}
async function accounts(st, req, secret, ctx) {
  const a = await getAcc(st), usr = who(req, secret, a);
  if (!usr || usr.role !== "admin") return J({ error: "forbidden" }, usr ? 403 : 401);
  if (req.method === "GET") return J({ users: a.users.map(({ u, n, role, st, t }) => ({ u, n, role, st, t })) });
  if (req.method !== "POST") return J({ error: "method" }, 405);
  const b = await body(req); if (!b) return bad();
  if (b.action === "purge") { // remove every member (admin accounts stay); needs a fresh rotating code
    const step = checkTotp(usr.totp, b.code); if (!step) return J({ error: "code" }, 401);
    usr.totp.ls = step; a.users = a.users.filter((x) => x.role === "admin"); a.devs = {};
    await saveAcc(st, a); await audit(st, "members_purged", usr.u, ctx);
    return J({ ok: true });
  }
  const t = a.users.find((x) => x.u === norm(b.u));
  if (!t || t.role === "admin") return bad();
  const act = b.action;
  if (act === "approve" && t.st === "pending") t.st = "ok";
  else if (act === "reject" && t.st === "pending") a.users = a.users.filter((x) => x !== t);
  else if (act === "suspend" && t.st === "ok") t.st = "off";
  else if (act === "restore" && t.st === "off") t.st = "ok";
  else if (act === "delete") a.users = a.users.filter((x) => x !== t);
  else return bad();
  await saveAcc(st, a); await audit(st, "account_" + act, usr.u, ctx, { target: t.u });
  return J({ ok: true });
}

export default async (req, ctx) => {
  const st = store(), path = new URL(req.url).pathname.replace(/^\/api\//, "").replace(/\/+$/, "");
  try {
    if (path === "state" && req.method === "GET") return await getState(st, req);
    const secret = await getSecret(st), m = req.method;
    if (path === "state" && m === "PUT") return await putState(st, req, secret);
    if (path === "login" && m === "POST") return await login(st, req, secret, ctx);
    if (path === "login2" && m === "POST") return await login2(st, req, secret, ctx);
    if (path === "register" && m === "POST") return await register(st, req, ctx);
    if (path === "change-pin" && m === "POST") return await changePin(st, req, secret, ctx);
    if (path === "2fa/confirm" && m === "POST") return await confirm2fa(st, req, secret, ctx);
    if (path === "unlock" && m === "POST") return await unlock(st, req, ctx);
    if (path === "recover" && m === "POST") return await recover(st, req, secret, ctx);
    if (path === "device/register" && m === "POST") return await deviceRegister(st, req, secret, ctx);
    if (path === "device/login" && m === "POST") return await deviceLogin(st, req, secret, ctx);
    if (path === "device/remove" && m === "POST") return await deviceRemove(st, req, secret);
    if (path === "lockdown" && m === "POST") return await lockdown(st, req, secret, ctx);
    if (path === "signout-all" && m === "POST") return await signoutAll(st, req, secret, ctx);
    if (path === "security" && m === "GET") return await security(st, req, secret);
    if (path === "accounts") return await accounts(st, req, secret, ctx);
    return J({ error: "not_found" }, 404);
  } catch (e) { console.error(e); return J({ error: "server" }, 500); }
};
export const config = { path: "/api/*" };
