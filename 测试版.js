/**  
* Telegram Bot Worker v3.85 (Customized)
* 已移除备份功能，新增自动化就寝时间功能
*/  
  
// --- 1. 静态配置与常量 ---  
const CACHE = {  
  data: {},  
  ts: 0,  
  ttl: 60000,  
  locks: new Set(),  
  admin: {  
    ts: 0,  
    ttl: 60000,  
    primarySet: new Set(),  
    authSet: new Set()  
  },  
  cleanup: {  
    processed_updates_ts: 0,  
    ratelimits_ts: 0,  
    messages_ts: 0  
  }  
};  
  
const DEFAULTS = {  
  // 基础  
  welcome_msg: "欢迎 {name}!请先完成验证。",  
  
  // 验证  
  enable_verify: "true",  
  enable_qa_verify: "true",  
  captcha_mode: "turnstile",  
  verif_q: "1+1=?\n提示:答案在简介中。",  
  verif_a: "2",  
  
  // 风控  
  block_threshold: "5",  
  enable_admin_receipt: "true",  
  
  // 转发开关  
  enable_image_forwarding: "true",  
  enable_link_forwarding: "true",  
  enable_text_forwarding: "true",  
  enable_channel_forwarding: "true",  
  enable_forward_forwarding: "true",  
  enable_audio_forwarding: "true",  
  enable_sticker_forwarding: "true",  
  
  // 话题与列表 (已移除 backup_group_id)
  unread_topic_id: "",  
  blocked_topic_id: "",  
  // 就寝时间功能
  enable_sleep_mode: "false",  
  sleep_start: "23:00",
  sleep_end: "07:00",
  sleep_msg: "当前是管理员就寝时间，消息已收到，管理员醒后会第一时间回复。",  
  block_keywords: "[]",  
  keyword_responses: "[]",  
  authorized_admins: "[]"  
};  
  
const DELIVERED_REACTION = "👍";  
  
// 幂等/限流/锁参数  
const PROCESSED_UPDATES_TTL_MS = 7 * 24 * 60 * 60 * 1000;  
const RATELIMIT_CLEANUP_TTL_MS = 10 * 60 * 1000;  
const RATELIMIT_USER_WINDOW_MS = 2000;  
const RATELIMIT_USER_MAX = 6;  
const RATELIMIT_GLOBAL_WINDOW_MS = 10000;  
const RATELIMIT_GLOBAL_MAX = 250;  
const SUBMIT_RL_WINDOW_MS = 60000;  
const SUBMIT_RL_IP_MAX = 30;  
const SUBMIT_RL_UID_MAX = 10;  
const TOPIC_LOCK_STALE_MS = 60 * 1000;  
const TOPIC_LOCK_POLL_MAX = 8;  
const TOPIC_LOCK_POLL_BASE_MS = 160;  
const VERIFY_NONCE_TTL_MS = 15 * 60 * 1000;  
const MESSAGES_TTL_DAYS = 30;  
  
// Regex 安全策略  
const REGEX_MAX_PATTERN_LEN = 256;  
const REGEX_MAX_TEXT_LEN = 512;  
const REGEX_REJECT_PATTERNS = [  
  /\([^)]*\)\s*[+*{]/,  
  /\(\s*\.\*\s*\)\s*\+/,  
  /\(\s*\.\+\s*\)\s*\+/,  
  /\\[1-9]/,  
  /\(\?<=[\s\S]*\)/,  
  /\(\?<![\s\S]*\)/  
];  
  
const MSG_TYPES = [  
  {  
    check: m => m.forward_from || m.forward_from_chat,  
    key: "enable_forward_forwarding",  
    name: "转发消息",  
    extra: m => (m.forward_from_chat?.type === "channel" ? "enable_channel_forwarding" : null)  
  },  
  { check: m => m.audio || m.voice, key: "enable_audio_forwarding", name: "语音/音频" },  
  { check: m => m.sticker || m.animation, key: "enable_sticker_forwarding", name: "贴纸/GIF" },  
  { check: m => m.photo || m.video || m.document, key: "enable_image_forwarding", name: "媒体文件" },  
  { check: m => (m.entities || []).some(e => ["url", "text_link"].includes(e.type)), key: "enable_link_forwarding", name: "链接" },  
  { check: m => m.text, key: "enable_text_forwarding", name: "纯文本" }  
];  
  
// --- 2. 核心入口 ---  
export default {  
  async fetch(req, env, ctx) {  
    ctx.waitUntil(dbInit(env).catch(e => console.error("DB Init Failed:", e)));  
  
    const url = new URL(req.url);  
  
    try {  
      if (req.method === "GET") {  
        if (url.pathname === "/verify") return handleVerifyPage(url, env);  
        if (url.pathname === "/") return new Response("Bot v3.85 (Sleep Mode Active)", { status: 200 });  
      }  
  
      if (req.method === "POST") {  
        if (url.pathname === "/submit_token") return handleTokenSubmit(req, env, ctx);  
  
        if (!isTelegramWebhook(req, env)) {  
          return new Response("Forbidden", { status: 403 });  
        }  
  
        try {  
          const update = await req.json();  
          const ok = await markUpdateOnce(update, env, ctx);  
          if (!ok) return new Response("OK");  
  
          ctx.waitUntil(handleUpdate(update, env, ctx));  
          return new Response("OK");  
        } catch {  
          return new Response("Bad Request", { status: 400 });  
        }  
      }  
    } catch (e) {  
      console.error("Critical Worker Error:", e);  
      return new Response("Internal Server Error", { status: 500 });  
    }  
  
    return new Response("404 Not Found", { status: 404 });  
  }  
};  
  
// --- 3. 数据库封装 ---  
const safeParse = (str, fb = {}) => {  
  try { return JSON.parse(str); } catch { return fb; }  
};  
  
const sql = async (env, query, args = [], type = "run") => {  
  try {  
    const stmt = env.TG_BOT_DB.prepare(query).bind(...(Array.isArray(args) ? args : [args]));  
    return type === "run" ? await stmt.run() : await stmt[type]();  
  } catch (e) {  
    console.error(`SQL Fail [${query}]:`, e);  
    if (query.match(/^(INSERT|UPDATE|DELETE|REPLACE|ALTER|CREATE)/i)) throw e;  
    return null;  
  }  
};  
  
const tryRun = async (env, query, args = []) => {  
  try {  
    const stmt = env.TG_BOT_DB.prepare(query).bind(...(Array.isArray(args) ? args : [args]));  
    return await stmt.run();  
  } catch { return null; }  
};  
  
async function getCfg(k, env) {  
  const now = Date.now();  
  if (CACHE.ts && now - CACHE.ts < CACHE.ttl && CACHE.data[k] !== undefined) return CACHE.data[k];  
  const rows = await sql(env, "SELECT * FROM config", [], "all");  
  if (rows?.results) {  
    CACHE.data = {};  
    rows.results.forEach(r => (CACHE.data[r.key] = r.value));  
    CACHE.ts = now;  
  }  
  const envK = k.toUpperCase().replace(/_MSG|_Q|_A/, m => ({ _MSG: "_MESSAGE", _Q: "_QUESTION", _A: "_ANSWER" }[m]));  
  return CACHE.data[k] ?? (env[envK] || DEFAULTS[k] || "");  
}  
  
async function setCfg(k, v, env) {  
  await sql(env, "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", [k, v]);  
  CACHE.ts = 0;  
}  
  
async function getUser(id, env) {  
  let u = await sql(env, "SELECT * FROM users WHERE user_id = ?", id, "first");  
  if (!u) {  
    try {  
      await sql(env, "INSERT OR IGNORE INTO users (user_id, user_state, user_info_json) VALUES (?, 'new', ?)", [id, "{}"]);  
    } catch {}  
    u = await sql(env, "SELECT * FROM users WHERE user_id = ?", id, "first");  
  }  
  if (!u) {  
    u = { user_id: id, user_state: "new", is_blocked: 0, block_count: 0, topic_id: null, user_info_json: "{}", topic_creating: 0, topic_create_ts: 0 };  
  }  
  u.is_blocked = !!u.is_blocked;  
  u.user_info = safeParse(u.user_info_json, {});  
  u.topic_creating = !!u.topic_creating;  
  u.topic_create_ts = u.topic_create_ts || 0;  
  return u;  
}  
  
async function mergeUserInfo(id, patch, env) {  
  const row = await sql(env, "SELECT user_info_json FROM users WHERE user_id = ?", id, "first");  
  const cur = safeParse(row?.user_info_json || "{}", {});  
  const merged = { ...(cur && typeof cur === "object" ? cur : {}), ...(patch && typeof patch === "object" ? patch : {}) };  
  return JSON.stringify(merged);  
}  
  
async function updUser(id, data, env) {  
  if (data.user_info) {  
    data.user_info_json = await mergeUserInfo(id, data.user_info, env);  
    delete data.user_info;  
  }  
  const keys = Object.keys(data);  
  if (!keys.length) return;  
  const safeKeys = keys.filter(k => ["user_state", "is_blocked", "block_count", "topic_id", "user_info_json", "topic_creating", "topic_create_ts"].includes(k));  
  if (!safeKeys.length) return;  
  const q = `UPDATE users SET ${safeKeys.map(k => `${k}=?`).join(",")} WHERE user_id=?`;  
  const v = [...safeKeys.map(k => (typeof data[k] === "boolean" ? (data[k] ? 1 : 0) : data[k])), id];  
  try { await sql(env, q, v); } catch (e) { console.error("Update User Failed:", e); }  
}  
  
async function dbInit(env) {  
  if (!env.TG_BOT_DB) return;  
  
  await env.TG_BOT_DB.batch([  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS users (  
      user_id TEXT PRIMARY KEY, user_state TEXT DEFAULT 'new', is_blocked INTEGER DEFAULT 0, block_count INTEGER DEFAULT 0,  
      topic_id TEXT, user_info_json TEXT DEFAULT '{}', topic_creating INTEGER DEFAULT 0, topic_create_ts INTEGER DEFAULT 0  
    )`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS messages (  
      user_id TEXT, message_id TEXT, text TEXT, date INTEGER, PRIMARY KEY (user_id, message_id)  
    )`),  
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date)`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS processed_updates (update_id TEXT PRIMARY KEY, ts INTEGER)`),  
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_processed_updates_ts ON processed_updates(ts)`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS ratelimits (key TEXT PRIMARY KEY, ts INTEGER, count INTEGER)`),  
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_ratelimits_ts ON ratelimits(ts)`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS msg_mapping (  
      user_id TEXT, user_msg_id TEXT, admin_msg_id TEXT, ts INTEGER, PRIMARY KEY (user_id, user_msg_id)  
    )`),  
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_msg_mapping ON msg_mapping(admin_msg_id)`)  
  ]);  
  
  await ensureUserColumns(env);  
}  
  
async function ensureUserColumns(env) {  
  const info = await sql(env, "PRAGMA table_info(users)", [], "all");  
  const cols = new Set((info?.results || []).map(r => r.name));  
  const alters = [];  
  if (!cols.has("topic_creating")) alters.push(`ALTER TABLE users ADD COLUMN topic_creating INTEGER DEFAULT 0`);  
  if (!cols.has("topic_create_ts")) alters.push(`ALTER TABLE users ADD COLUMN topic_create_ts INTEGER DEFAULT 0`);  
  for (const q of alters) { try { await sql(env, q); } catch {} }  
}  
  
// --- 4. Telegram API ---  
async function api(token, method, body) {  
  const maxRetries = 3;  
  const baseBackoff = [200, 500, 1200];  
  const totalWaitCapMs = 10000;  
  let waited = 0;  
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {  
    try {  
      const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {  
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)  
      });  
      const d = await r.json().catch(() => null);  
      if (r.status >= 500) throw new Error(`HTTP_${r.status}`);  
      if (!d || !d.ok) {  
        const errCode = d?.error_code || r.status || 0;  
        if (errCode === 429 && attempt < maxRetries) {  
          const retryAfterSec = Number(d?.parameters?.retry_after || 0);  
          const delayMs = Math.min(5000, Math.max(200, (retryAfterSec ? retryAfterSec * 1000 : baseBackoff[attempt] || 1200)));  
          if (waited + delayMs > totalWaitCapMs) break;  
          waited += delayMs;  
          await sleep(delayMs);  
          continue;  
        }  
        const desc = d?.description || `TG API Error (${errCode})`;  
        if (method !== "setMessageReaction") console.warn(`TG API Error [${method}]:`, desc);  
        throw new Error(desc);  
      }  
      return d.result;  
    } catch (e) {  
      if (attempt < maxRetries) {  
        const delayMs = baseBackoff[attempt] || 1200;  
        if (waited + delayMs > totalWaitCapMs) break;  
        waited += delayMs;  
        await sleep(delayMs);  
        continue;  
      }  
      if (method !== "setMessageReaction") console.warn(`TG API Fail [${method}]:`, e?.message || e);  
      throw e;  
    }  
  }  
  throw new Error(`TG API Retry Exhausted: ${method}`);  
}  
  
// --- 5. Webhook 校验 / 幂等 / 限流 / 清理 ---  
function isTelegramWebhook(req, env) {  
  const secret = (env.TELEGRAM_WEBHOOK_SECRET || "").toString();  
  if (!secret) return false;  
  const hdr = req.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";  
  return timingSafeEqualStr(hdr, secret);  
}  
  
function safeWaitUntil(ctx, p) {  
  try { if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p); else p.catch(() => {}); } catch { try { p.catch(() => {}); } catch {} }  
}  
  
function maybeCleanup(ctx, key, fn, minIntervalMs) {  
  const now = Date.now();  
  const last = CACHE.cleanup[key] || 0;  
  if (now - last < minIntervalMs) return;  
  CACHE.cleanup[key] = now;  
  safeWaitUntil(ctx, fn());  
}  
  
async function markUpdateOnce(update, env, ctx) {  
  try {  
    const uid = (update && (update.update_id ?? update.updateId))?.toString();  
    if (!uid) return true;  
    const now = Date.now();  
    const res = await tryRun(env, "INSERT OR IGNORE INTO processed_updates (update_id, ts) VALUES (?,?)", [uid, now]);  
    const changes = res?.meta?.changes ?? res?.changes ?? 0;  
    if (!changes) return false;  
    if ((now % 97) === 7) {  
      maybeCleanup(ctx, "processed_updates_ts", async () => {  
        const cutoff = now - PROCESSED_UPDATES_TTL_MS;  
        await sql(env, "DELETE FROM processed_updates WHERE ts < ?", cutoff);  
      }, 60_000);  
    }  
    return true;  
  } catch { return true; }  
}  
  
async function bumpRateKey(env, key, now) {  
  const q = `INSERT INTO ratelimits (key, ts, count) VALUES (?, ?, 1) ON CONFLICT(key) DO UPDATE SET count = ratelimits.count + 1, ts = excluded.ts RETURNING count`;  
  const row = await sql(env, q, [key, now], "first");  
  return Number(row?.count || 0);  
}  
  
async function checkRateLimit(userId, env, ctx) {  
  const now = Date.now();  
  const uid = userId?.toString() || "";  
  if (!uid) return { allowed: true, retryAfterMs: 0 };  
  const userBucket = Math.floor(now / RATELIMIT_USER_WINDOW_MS);  
  const globalBucket = Math.floor(now / RATELIMIT_GLOBAL_WINDOW_MS);  
  const userKey = `u:${uid}:${userBucket}`;  
  const globalKey = `g:${globalBucket}`;  
  const [uc, gc] = await Promise.all([bumpRateKey(env, userKey, now), bumpRateKey(env, globalKey, now)]);  
  if ((now % 101) === 13) {  
    maybeCleanup(ctx, "ratelimits_ts", async () => {  
      const cutoff = now - RATELIMIT_CLEANUP_TTL_MS;  
      await sql(env, "DELETE FROM ratelimits WHERE ts < ?", cutoff);  
    }, 60_000);  
  }  
  if (gc > RATELIMIT_GLOBAL_MAX) return { allowed: false, retryAfterMs: RATELIMIT_GLOBAL_WINDOW_MS };  
  if (uc > RATELIMIT_USER_MAX) return { allowed: false, retryAfterMs: RATELIMIT_USER_WINDOW_MS };  
  return { allowed: true, retryAfterMs: 0 };  
}  
  
async function checkSubmitRateLimit(req, env, ctx, uidMaybe) {  
  const now = Date.now();  
  const ip = (req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "").split(",")[0].trim() || "0.0.0.0";  
  const bucket = Math.floor(now / SUBMIT_RL_WINDOW_MS);  
  const ipKey = `s:ip:${ip}:${bucket}`;  
  const ipCount = await bumpRateKey(env, ipKey, now);  
  if (ipCount > SUBMIT_RL_IP_MAX) return { allowed: false, reason: "ip" };  
  if (uidMaybe) {  
    const uKey = `s:u:${uidMaybe}:${bucket}`;  
    const uCount = await bumpRateKey(env, uKey, now);  
    if (uCount > SUBMIT_RL_UID_MAX) return { allowed: false, reason: "uid" };  
  }  
  return { allowed: true };  
}  
  
function maybeCleanupMessages(env, ctx) {  
  const now = Date.now();  
  if ((now % 131) !== 11) return;  
  maybeCleanup(ctx, "messages_ts", async () => {  
    const cutoffSec = Math.floor(now / 1000) - MESSAGES_TTL_DAYS * 86400;  
    await sql(env, "DELETE FROM messages WHERE date < ?", cutoffSec);  
  }, 10 * 60_000);  
}  
  
// --- 6. 主 update 分发 ---  
async function handleUpdate(update, env, ctx) {  
  const msg = update.message || update.edited_message;  
  if (!msg) return update.callback_query ? handleCallback(update.callback_query, env) : null;  
  
  if (update.message && msg.text === "/del" && msg.reply_to_message) {  
    return handleDeleteSync(msg, env);  
  }  

  if (update.message && msg.text === "/del" && !msg.reply_to_message) {
    return api(env.BOT_TOKEN, "sendMessage", { 
      chat_id: msg.chat.id, 
      text: "<b>⚠️ 使用提示:</b>\n引用你要撤回的消息,然后发送 /del", 
      parse_mode: "HTML"
    });
  }
    
  if (update.edited_message) {  
    return handleEditSync(update.edited_message, env);  
  }  
  
  if (msg.chat.type === "private") await handlePrivate(msg, env, ctx);  
  else if (msg.chat.id.toString() === env.ADMIN_GROUP_ID) await handleAdminReply(msg, env);  
}  
  
// --- 7. 管理员集合 ---  
function parseIdsToSet(str) {  
  return new Set((str || "").toString().split(/[,,]/).map(s => s.trim()).filter(Boolean));  
}  
  
async function getAdminSets(env) {  
  const now = Date.now();  
  if (CACHE.admin.ts && now - CACHE.admin.ts < CACHE.admin.ttl && CACHE.admin.primarySet.size) {  
    return { primary: CACHE.admin.primarySet, auth: CACHE.admin.authSet };  
  }  
  const primary = parseIdsToSet(env.ADMIN_IDS || "");  
  const authList = await getJsonCfg("authorized_admins", env);  
  const auth = new Set([...primary, ...((Array.isArray(authList) ? authList : []).map(x => x.toString()))]);  
  CACHE.admin.ts = now;  
  CACHE.admin.primarySet = primary;  
  CACHE.admin.authSet = auth;  
  return { primary, auth };  
}  
  
async function isPrimaryAdmin(id, env) {  
  const sets = await getAdminSets(env);  
  return sets.primary.has(id.toString());  
}  
  
async function isAuthAdmin(id, env) {  
  const sets = await getAdminSets(env);  
  return sets.auth.has(id.toString());  
}  
  
// --- 8. 私聊处理 ---  
async function handlePrivate(msg, env, ctx) {  
  const id = msg.chat.id.toString();  
  const text = msg.text || "";  
  const isStart = text.startsWith("/start");  
  
  const u0 = await getUser(id, env);  
  if (u0.is_blocked && !(await isAuthAdmin(id, env))) {  
    const bk = `blocked_notice:${id}`;  
    if (!CACHE.locks.has(bk)) {  
      CACHE.locks.add(bk);  
      setTimeout(() => CACHE.locks.delete(bk), 10000);  
      api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🚫 您已被管理员屏蔽,无法发送消息。" }).catch(() => {});  
    }  
    return;  
  }  
  
  if (!(await isAuthAdmin(id, env))) {  
    const rl = await checkRateLimit(id, env, ctx);  
    if (!rl.allowed) {  
      const warnKey = `rlwarn:${id}`;  
      if (!CACHE.locks.has(warnKey)) {  
        CACHE.locks.add(warnKey);  
        setTimeout(() => CACHE.locks.delete(warnKey), 10000);  
        api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "⏳ 请求过于频繁,请稍后再试。" }).catch(() => {});  
      }  
      return;  
    }  
  }  
  
  if (text.startsWith("/reset") && (await isPrimaryAdmin(id, env))) {  
    const parts = text.trim().split(/\s+/);  
    const target = (parts[1] || "").trim();  
    if (!target || !/^\d+$/.test(target)) return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "用法:/reset <user_id>" });  
    await forceResetUserVerify(target, env);  
    api(env.BOT_TOKEN, "sendMessage", { chat_id: target, text: "⚠️ 管理员要求您重新验证。\n请发送 /start 重新完成验证流程。" }).catch(() => {});  
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `✅ 已重置用户 ${target} 的验证状态。` });  
  }  
  
  if (isStart && (await isPrimaryAdmin(id, env))) {  
    if (ctx) ctx.waitUntil(registerCommands(env));  
    return handleAdminConfig(id, null, "menu", null, null, env);  
  }  
  
  if (text === "/help" && (await isAuthAdmin(id, env))) {  
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "ℹ️ <b>帮助</b>\n• 回复消息即对话\n• /start 打开面板\n• /del 双向撤回\n• /reset <id> 重置验证", parse_mode: "HTML" });  
  }  
  
  const u = u0;  
  if (await isAuthAdmin(id, env)) {  
    if (u.user_state !== "verified") await updUser(id, { user_state: "verified" }, env);  
  }  
  
  if (await isPrimaryAdmin(id, env)) {  
    const stateStr = await getCfg(`admin_state:${id}`, env);  
    if (stateStr) {  
      const state = safeParse(stateStr);  
      if (state.action === "input") return handleAdminInput(id, msg, state, env);  
    }  
  }  
  
  const verifyOn = await getBool("enable_verify", env);  
  const qaOn = await getBool("enable_qa_verify", env);  
  if (u.user_state !== "verified" && (verifyOn || qaOn)) {  
    if (u.user_state === "pending_verification" && text) return verifyAnswer(id, text, env);  
    return sendStart(id, msg, env);  
  }  
  
  if (isStart) {  
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: u.topic_id ? "✅ <b>会话已连接</b>\n可以直接发送消息。" : "✅ 已验证。\n请直接发送消息以联系管理员。", parse_mode: "HTML" });  
    return;  
  }  
  
  await handleVerifiedMsg(msg, u, env, ctx);  
}  
  
async function forceResetUserVerify(userId, env) {  
  const uid = userId.toString();  
  await updUser(uid, { user_state: "new", user_info: { verify_nonce: "", verify_nonce_ts: 0 } }, env);  
}  
  
// --- 9. Start 流程 ---  
async function sendStart(id, msg, env) {  
  const u = await getUser(id, env);  
  if (u.is_blocked && !(await isAuthAdmin(id, env))) return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🚫 您已被管理员屏蔽。" }).catch(() => {});  
    
  if (u.user_state === "verified") {  
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: u.topic_id ? "✅ <b>会话已连接</b>" : "✅ 已验证。", parse_mode: "HTML" });  
  }  
  
  let welcomeRaw = await getCfg("welcome_msg", env);  
  const name = escapeHTML(msg.from.first_name || "User");  
  let media = null, txt = welcomeRaw;  
  try {  
    if (welcomeRaw.trim().startsWith("{")) {  
      media = safeParse(welcomeRaw, null);  
      if (media) txt = media.caption || "";  
    }  
  } catch {}  
  txt = txt.replace(/{name}|{user}/g, name);  
  
  if (media && media.type) {  
    try {  
      await api(env.BOT_TOKEN, `send${media.type.charAt(0).toUpperCase() + media.type.slice(1)}`, { chat_id: id, [media.type]: media.file_id, caption: txt, parse_mode: "HTML" });  
    } catch {  
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: txt, parse_mode: "HTML" });  
    }  
  } else {  
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: txt, parse_mode: "HTML" });  
  }  
  
  const url = (env.WORKER_URL || "").replace(/\/$/, "");  
  const vOn = await getBool("enable_verify", env);  
  const qaOn = await getBool("enable_qa_verify", env);  
  
  if (vOn && url) {  
    const nonce = genNonce(24);  
    await updUser(id, { user_state: "pending_turnstile", user_info: { verify_nonce: nonce, verify_nonce_ts: Date.now() } }, env);  
    await api(env.BOT_TOKEN, "sendMessage", {  
      chat_id: id, text: "🛡️ <b>安全验证</b>\n请点击下方按钮完成验证。", parse_mode: "HTML",  
      reply_markup: { inline_keyboard: [[{ text: "点击进行验证", web_app: { url: `${url}/verify?user_id=${encodeURIComponent(id)}&nonce=${encodeURIComponent(nonce)}` } }]] }  
    });  
  } else if (qaOn) {  
    await updUser(id, { user_state: "pending_verification" }, env);  
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❓ <b>安全提问</b>\n" + (await getCfg("verif_q", env)), parse_mode: "HTML" });  
  } else {  
    await updUser(id, { user_state: "verified" }, env);  
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "✅ 已验证。" });  
  }  
}  
  
// --- 10. 已验证用户逻辑 (新增自动化就寝判定) ---  
async function handleVerifiedMsg(msg, u, env, ctx) {  
  const id = u.user_id;  
  if (u.is_blocked && !(await isAuthAdmin(id, env))) return;  
  const text = msg.text || msg.caption || "";  
  
  if (text) {  
    const kws = await getJsonCfg("block_keywords", env);  
    const hit = (Array.isArray(kws) ? kws : []).some(k => safeRegexTest(k, text));  
    if (hit) {  
      const c = u.block_count + 1;  
      const max = parseInt(await getCfg("block_threshold", env), 10) || 5;  
      await updUser(id, { block_count: c, is_blocked: c >= max }, env);  
      if (c >= max) {  
        await manageBlacklist(env, u, msg.from, true);  
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 您已被系统自动封禁" });  
      }  
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `⚠️ 含有违禁词 (${c}/${max})` });  
    }  
  }  
  
  for (const t of MSG_TYPES) {  
    if (t.check(msg)) {  
      const enabled = t.extra ? await getBool(t.extra(msg), env) : await getBool(t.key, env);  
      if (!enabled && !(await isAuthAdmin(id, env))) return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `⚠️ 系统不接收 ${t.name}` });  
      break;  
    }  
  }  
  
  if (text) {  
    const rules = await getJsonCfg("keyword_responses", env);  
    const match = (Array.isArray(rules) ? rules : []).find(r => r && safeRegexTest(r.keywords, text));  
    if (match) api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: match.response }).catch(() => {});  
  }  
  
  // 就寝时间逻辑 (自动化)
  if (await getBool("enable_sleep_mode", env)) {  
    const now = new Date();
    const currentTime = now.toLocaleTimeString('zh-CN', { hour12: false, timeZone: 'Asia/Shanghai' }).slice(0, 5);
    const start = await getCfg("sleep_start", env);
    const end = await getCfg("sleep_end", env);
    
    let isSleeping = false;
    if (start <= end) {
      isSleeping = (currentTime >= start && currentTime <= end);
    } else {
      isSleeping = (currentTime >= start || currentTime <= end); // 跨天
    }

    if (isSleeping) {
      const nowTs = Date.now();  
      if (nowTs - (u.user_info.last_sleep_reply || 0) > 300000) {  
        api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🌙 " + (await getCfg("sleep_msg", env)) }).catch(() => {});  
        await updUser(id, { user_info: { last_sleep_reply: nowTs } }, env);  
      }  
    }
  }  
  
  await relayToTopic(msg, u, env, ctx);  
}  
  
// --- 11. 转发到话题 (已移除备份调用) ---  
async function relayToTopic(msg, u, env, ctx) {  
  const uid = u.user_id;  
  if (u.is_blocked && !(await isAuthAdmin(uid, env))) return;  
  const uMeta = getUMeta(msg.from, u, msg.date);  
  let tid = u.topic_id;  
  
  if (!tid) {  
    const now = Date.now();  
    const staleBefore = now - TOPIC_LOCK_STALE_MS;  
    const lockRes = await tryRun(env, `UPDATE users SET topic_creating=1, topic_create_ts=? WHERE user_id=? AND (topic_id IS NULL OR topic_id='') AND (topic_creating=0 OR topic_create_ts < ?)`, [now, uid, staleBefore]);  
    const locked = (lockRes?.meta?.changes ?? lockRes?.changes ?? 0) === 1;  
  
    if (locked) {  
      try {  
        const fresh = await getUser(uid, env);  
        if (fresh.topic_id) { tid = fresh.topic_id; }  
        else {  
          const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: uMeta.topicName });  
          tid = t.message_thread_id.toString();  
          await updUser(uid, { topic_id: tid, topic_creating: 0, topic_create_ts: 0 }, env);  
          u.topic_id = tid;  
          await sendInfoCardToTopic(env, u, msg.from, tid);  
        }  
      } catch (e) {  
        console.error("Topic Create Error:", e);  
        await updUser(uid, { topic_creating: 0 }, env);  
        const existUser = await getUser(uid, env);  
        if (existUser.topic_id) tid = existUser.topic_id;  
        else return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙,请稍后重试" });  
      }  
    } else {  
      for (let i = 0; i < TOPIC_LOCK_POLL_MAX; i++) {  
        await sleep(Math.min(1500, TOPIC_LOCK_POLL_BASE_MS * Math.pow(2, i)) + Math.floor(Math.random() * 60));  
        const fresh = await getUser(uid, env);  
        if (fresh.topic_id) { tid = fresh.topic_id; u.topic_id = tid; break; }  
      }  
      if (!tid) return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙,请稍后重试" });  
    }  
  }  
  
  if (!tid) return;  
  
  let relaySuccess = false;  
  let sentMsgId = null;  
  let replyToIdInAdmin = null;  
  if (msg.reply_to_message) {  
    try {  
      const ref = await sql(env, "SELECT admin_msg_id FROM msg_mapping WHERE user_id = ? AND user_msg_id = ?",  
        [uid, msg.reply_to_message.message_id.toString()], "first");  
      if (ref) replyToIdInAdmin = ref.admin_msg_id;  
    } catch {}  
  }  
  
  try {  
    const extra = {};  
    if (msg.text) extra.text = msg.text;  
    if (msg.caption) extra.caption = msg.caption;  
      
    const res = await api(env.BOT_TOKEN, "copyMessage", {  
      chat_id: env.ADMIN_GROUP_ID,  
      from_chat_id: uid,  
      message_id: msg.message_id,  
      message_thread_id: tid,  
      reply_to_message_id: replyToIdInAdmin,  
      ...extra  
    });  
  
    if (res && res.message_id) {  
      sentMsgId = res.message_id;  
      relaySuccess = true;  
      await sql(env, "INSERT OR REPLACE INTO msg_mapping (user_id, user_msg_id, admin_msg_id, ts) VALUES (?, ?, ?, ?)",  
        [uid, msg.message_id.toString(), sentMsgId.toString(), Date.now()]);  
    }  
  } catch (cpErr) {  
    if (cpErr.message && (cpErr.message.includes("thread") || cpErr.message.includes("not found"))) {  
      await updUser(uid, { topic_id: null }, env);  
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 会话已过期,请重发" });  
    }  
  }  
  
  if (relaySuccess) {  
    const dk = `delivered:${uid}:${msg.message_id}`;  
    if (!CACHE.locks.has(dk)) {  
      CACHE.locks.add(dk);  
      setTimeout(() => CACHE.locks.delete(dk), 20000);  
      markDelivered(env, uid, msg.message_id);  
    }  
  
    if (msg.text) {  
      try {  
        await sql(env, "INSERT OR REPLACE INTO messages (user_id, message_id, text, date) VALUES (?,?,?,?)", [uid, msg.message_id, msg.text, msg.date]);  
      } catch {}  
      maybeCleanupMessages(env, ctx);  
    }  
    await handleInbox(env, msg, u, tid, uMeta);  
  }  
}  
  
async function markDelivered(env, chatId, messageId) {  
  try {  
    await api(env.BOT_TOKEN, "setMessageReaction", {  
      chat_id: chatId, message_id: messageId, reaction: [{ type: "emoji", emoji: DELIVERED_REACTION }], is_big: false  
    });  
  } catch {}  
}  
  
// --- 12. 资料卡 ---  
async function sendInfoCardToTopic(env, u, tgUser, tid, date) {  
  const meta = getUMeta(tgUser, u, date || Date.now() / 1000);  
  try {  
    const card = await api(env.BOT_TOKEN, "sendMessage", {  
      chat_id: env.ADMIN_GROUP_ID, message_thread_id: tid, text: meta.card, parse_mode: "HTML", reply_markup: getBtns(u.user_id, u.is_blocked)  
    });  
    await updUser(u.user_id, { user_info: { card_msg_id: card.message_id } }, env);  
    api(env.BOT_TOKEN, "pinChatMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: card.message_id, message_thread_id: tid }).catch(() => {});  
    return card.message_id;  
  } catch { return null; }  
}  
  
// --- 13. 未读通知 ---  
async function handleInbox(env, msg, u, tid, uMeta) {  
  const lk = `inbox:${u.user_id}`;  
  if (CACHE.locks.has(lk)) return;  
  CACHE.locks.add(lk);  
  setTimeout(() => CACHE.locks.delete(lk), 3000);  
  
  let inboxId = await getCfg("unread_topic_id", env);  
  if (!inboxId) {  
    try {  
      const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: "🔔 未读消息" });  
      inboxId = t.message_thread_id.toString();  
      await setCfg("unread_topic_id", inboxId, env);  
    } catch { return; }  
  }  
  
  const gid = env.ADMIN_GROUP_ID.toString().replace(/^-100/, "");  
  const preview = msg.text ? (msg.text.length > 20 ? msg.text.substring(0, 20) + "..." : msg.text) : "[媒体消息]";  
  const cardText = `<b>🔔 新消息</b>\n${uMeta.card}\n📝 <b>预览:</b> ${escapeHTML(preview)}`;  
  const kb = { inline_keyboard: [[{ text: "🚀 直达回复", url: `https://t.me/c/${gid}/${tid}` }, { text: "✅ 已阅", callback_data: `inbox:del:${u.user_id}` }]] };  
  
  try {  
    if (u.user_info.inbox_msg_id) {  
      try {  
        await api(env.BOT_TOKEN, "editMessageText", {  
          chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.inbox_msg_id, message_thread_id: inboxId,  
          text: cardText, parse_mode: "HTML", reply_markup: kb  
        });  
        await updUser(u.user_id, { user_info: { last_notify: Date.now() } }, env);  
        return;  
      } catch {}  
    }  
    const nm = await api(env.BOT_TOKEN, "sendMessage", {  
      chat_id: env.ADMIN_GROUP_ID, message_thread_id: inboxId, text: cardText, parse_mode: "HTML", reply_markup: kb  
    });  
    await updUser(u.user_id, { user_info: { last_notify: Date.now(), inbox_msg_id: nm.message_id } }, env);  
  } catch (e) {  
    if (e.message && e.message.includes("thread")) await setCfg("unread_topic_id", "", env);  
  }  
}  
  
// --- 14. 黑名单 ---  
async function manageBlacklist(env, u, tgUser, isBlocking) {  
  let bid = await getCfg("blocked_topic_id", env);  
  if (!bid && isBlocking) {  
    try {  
      const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: "🚫 黑名单" });  
      bid = t.message_thread_id.toString();  
      await setCfg("blocked_topic_id", bid, env);  
    } catch { return; }  
  }  
  if (!bid) return;  
  
  if (isBlocking) {  
    const meta = getUMeta(tgUser, u, Date.now() / 1000);  
    const m = await api(env.BOT_TOKEN, "sendMessage", {  
      chat_id: env.ADMIN_GROUP_ID, message_thread_id: bid, text: `<b>🚫 用户已屏蔽</b>\n${meta.card}`, parse_mode: "HTML",  
      reply_markup: { inline_keyboard: [[{ text: "✅ 解除屏蔽", callback_data: `unblock:${u.user_id}` }]] }  
    }).catch(() => {});  
    if (m) await updUser(u.user_id, { user_info: { blacklist_msg_id: m.message_id } }, env);  
  } else {  
    if (u.user_info.blacklist_msg_id) {  
      api(env.BOT_TOKEN, "deleteMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.blacklist_msg_id }).catch(() => {});  
      await updUser(u.user_id, { user_info: { blacklist_msg_id: null } }, env);  
    }  
  }  
}  
  
// --- 15. Web 验证页 ---  
async function handleVerifyPage(url, env) {  
  const uid = url.searchParams.get("user_id");  
  const nonce = url.searchParams.get("nonce") || "";  
  const mode = await getCfg("captcha_mode", env);  
  const siteKey = mode === "recaptcha" ? env.RECAPTCHA_SITE_KEY : env.TURNSTILE_SITE_KEY;  
  if (!uid || !siteKey) return new Response("Misconfigured", { status: 400 });  
  
  const script = mode === "recaptcha" ? "https://www.google.com/recaptcha/api.js" : "https://challenges.cloudflare.com/turnstile/v0/api.js";  
  const divClass = mode === "recaptcha" ? "g-recaptcha" : "cf-turnstile";  
  
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">  
<script src="https://telegram.org/js/telegram-web-app.js"></script>  
<script src="${script}" async defer></script>  
<style>body{display:flex;justify-content:center;align-items:center;height:100vh;background:#fff;font-family:sans-serif}  
#c{text-align:center;padding:20px;background:#f0f0f0;border-radius:10px;max-width:92vw}</style></head>  
<body><div id="c"><h3>🛡️ 安全验证</h3><div class="${divClass}" data-sitekey="${siteKey}" data-callback="S"></div><div id="m"></div></div>  
<script>  
const tg=window.Telegram.WebApp;tg.ready();  
const UI_USER_ID='${escapeHTML(uid)}';  
const UI_NONCE='${escapeHTML(nonce)}';  
function S(t){  
  document.getElementById('m').innerText='Wait...';  
  const initData = tg.initData || "";  
  fetch('/submit_token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t,userId:UI_USER_ID,nonce:UI_NONCE,initData})})  
  .then(r=>r.json()).then(d=>{  
    if(d.success){ document.getElementById('m').innerText='✅'; setTimeout(()=>{tg.close();try{window.close()}catch(e){}},800); }  
    else{ document.getElementById('m').innerText='❌'; }  
  }).catch(e=>{document.getElementById('m').innerText='Error'});  
}  
</script></body></html>`;  
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });  
}  
  
async function handleTokenSubmit(req, env, ctx) {  
  try {  
    const body = await req.json();  
    const token = body?.token;  
    const uiUserId = (body?.userId || "").toString();  
    const nonce = (body?.nonce || "").toString();  
    const initData = (body?.initData || "").toString();  
    const mode = await getCfg("captcha_mode", env);  
  
    const rlPre = await checkSubmitRateLimit(req, env, ctx, "");  
    if (!rlPre.allowed) throw new Error("Rate limited");  
  
    if (!initData || initData.length < 20) throw new Error("Missing initData");  
    const parsed = await verifyTelegramInitData(initData, env.BOT_TOKEN, 600);  
    const uid = parsed?.userId?.toString();  
    if (!uid) throw new Error("Missing uid");  
  
    const rlUid = await checkSubmitRateLimit(req, env, ctx, uid);  
    if (!rlUid.allowed) throw new Error("Rate limited");  
    if (uiUserId && uiUserId !== uid) throw new Error("uid mismatch");  
  
    const u = await getUser(uid, env);  
    if (u.is_blocked && !(await isAuthAdmin(uid, env))) throw new Error("blocked");  
  
    const savedNonce = (u.user_info?.verify_nonce || "").toString();  
    const savedTs = Number(u.user_info?.verify_nonce_ts || 0);  
    const expired = !savedTs || Date.now() - savedTs > VERIFY_NONCE_TTL_MS;  
    if (u.user_state === "verified") return new Response(JSON.stringify({ success: true }));  
  
    const vOn = await getBool("enable_verify", env);  
    if (vOn) {  
      if (!nonce || !savedNonce || expired || nonce !== savedNonce) throw new Error("nonce invalid");  
      await updUser(uid, { user_info: { verify_nonce: "", verify_nonce_ts: 0 } }, env);  
    }  
  
    const verifyUrl = mode === "recaptcha" ? "https://www.google.com/recaptcha/api/siteverify" : "https://challenges.cloudflare.com/turnstile/v0/siteverify";  
    const params = mode === "recaptcha" ? new URLSearchParams({ secret: env.RECAPTCHA_SECRET_KEY, response: token }) : JSON.stringify({ secret: env.TURNSTILE_SECRET_KEY, response: token });  
    const headers = mode === "recaptcha" ? { "Content-Type": "application/x-www-form-urlencoded" } : { "Content-Type": "application/json" };  
      
    const r = await fetch(verifyUrl, { method: "POST", headers, body: params });  
    const d = await r.json();  
    if (!d.success) throw new Error("Token Invalid");  
  
    try {  
      if (parsed?.userObj) {  
        const nm = ((parsed.userObj.first_name || "") + " " + (parsed.userObj.last_name || "")).trim() || (parsed.userObj.first_name || "");  
        const patch = {};  
        if (nm) patch.name = nm;  
        if (parsed.userObj.username) patch.username = parsed.userObj.username.toString();  
        if (parsed.authDate) patch.join_date = parsed.authDate;  
        if (Object.keys(patch).length) await updUser(uid, { user_state: "verified", user_info: patch }, env);  
        else await updUser(uid, { user_state: "verified" }, env);
      } else {
        await updUser(uid, { user_state: "verified" }, env);
      }
    } catch { await updUser(uid, { user_state: "verified" }, env); }  
  
    const qaOn = await getBool("enable_qa_verify", env);  
    if (qaOn) {  
      await updUser(uid, { user_state: "pending_verification" }, env);  
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 验证通过!\n请继续回答:\n" + (await getCfg("verif_q", env)) });  
    } else {  
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 验证通过!\n请直接发送消息以联系管理员。" });  
    }  
    return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });  
  } catch {  
    return new Response(JSON.stringify({ success: false }), { status: 400 });  
  }  
}  
  
async function verifyAnswer(id, ans, env) {  
  if (ans.trim() === (await getCfg("verif_a", env)).trim()) {  
    await updUser(id, { user_state: "verified" }, env);  
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "✅ 验证通过!\n请直接发送消息以联系管理员。" });  
  } else {  
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 错误" });  
  }  
}  
  
// --- 16. initData 验签 ---  
async function verifyTelegramInitData(initData, botToken, maxAgeSec) {  
  const params = new URLSearchParams(initData);  
  const hash = params.get("hash");  
  if (!hash) throw new Error("missing hash");  
  const authDate = parseInt(params.get("auth_date") || "0", 10);  
  if (!authDate) throw new Error("missing auth_date");  
  if (maxAgeSec && Math.floor(Date.now() / 1000) - authDate > maxAgeSec) throw new Error("expired");  
  
  const pairs = [];  
  for (const [k, v] of params.entries()) {  
    if (k !== "hash") pairs.push([k, v]);  
  }  
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));  
  const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join("\n");  
    
  const secretKey = await hmacSha256Bytes(strToBytes("WebAppData"), strToBytes(botToken));  
  const calc = await hmacSha256Bytes(secretKey, strToBytes(dataCheckString));  
  if (!timingSafeEqualHex(bytesToHex(calc), hash)) throw new Error("hash mismatch");  
  
  let userObj = null;  
  try { userObj = JSON.parse(params.get("user") || "{}"); } catch {}  
  return { userId: userObj?.id, authDate, userObj };  
}  
  
function strToBytes(s) { return new TextEncoder().encode(s); }  
async function hmacSha256Bytes(k, d) {  
  const key = await crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);  
  const sig = await crypto.subtle.sign("HMAC", key, d);  
  return new Uint8Array(sig);  
}  
function bytesToHex(u8) { return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join(""); }  
function timingSafeEqualHex(a, b) {  
  const aa = (a || "").toLowerCase(), bb = (b || "").toLowerCase();  
  if (aa.length !== bb.length) return false;  
  let r = 0;  
  for (let i = 0; i < aa.length; i++) r |= aa.charCodeAt(i) ^ bb.charCodeAt(i);  
  return r === 0;  
}  
function timingSafeEqualStr(a, b) {  
  const aa = (a || "").toString(), bb = (b || "").toString();  
  if (aa.length !== bb.length) return false;  
  let r = 0;  
  for (let i = 0; i < aa.length; i++) r |= aa.charCodeAt(i) ^ bb.charCodeAt(i);  
  return r === 0;  
}  
  
// --- 17. 辅助函数 ---  
const getBool = async (k, e) => (await getCfg(k, e)) === "true";  
const getJsonCfg = async (k, e) => safeParse(await getCfg(k, e), []);  
function escapeHTML(t) { return (t || "").toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }  
function safeRegexTest(pattern, text) {  
  try {  
    const p = pattern?.trim();  
    if (!p || p.length > REGEX_MAX_PATTERN_LEN) return false;  
    for (const re of REGEX_REJECT_PATTERNS) if (re.test(p)) return false;  
    const t = (text || "").toString();  
    return new RegExp(p, "gi").test(t.length > REGEX_MAX_TEXT_LEN ? t.slice(0, REGEX_MAX_TEXT_LEN) : t);  
  } catch { return false; }  
}  
function genNonce(len) {  
  const bytes = new Uint8Array(len);  
  crypto.getRandomValues(bytes);  
  let s = "";  
  for (const b of bytes) s += (b % 36).toString(36);  
  return s;  
}  
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }  
const getUMeta = (tgUser, dbUser, d) => {  
  const id = tgUser.id.toString();  
  const name = (((tgUser.first_name || "") + " " + (tgUser.last_name || "")).trim() || tgUser.first_name || "User");  
  const timeStr = new Date(d * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });  
  const note = dbUser.user_info?.note ? `\n📝 <b>备注:</b> ${escapeHTML(dbUser.user_info.note)}` : "";  
  return { userId: id, name, topicName: `${name} | ${id}`.substring(0, 128), card: `<b>🪪 用户资料</b>\n👤: <code>${escapeHTML(name)}</code>\n🆔: <code>${escapeHTML(id)}</code>${note}\n🕒: <code>${escapeHTML(timeStr)}</code>` };  
};  
const getBtns = (id, blk) => ({ inline_keyboard: [[{ text: "👤 主页", url: `tg://user?id=${id}` }], [{ text: blk ? "✅ 解封" : "🚫 屏蔽", callback_data: `${blk ? "unblock" : "block"}:${id}` }], [{ text: "✏️ 备注", callback_data: `note:set:${id}` }, { text: "📌 置顶", callback_data: `pin_card:${id}` }]] });  
  
// --- 18. Commands ---  
async function registerCommands(env) {  
  try {  
    await api(env.BOT_TOKEN, "deleteMyCommands", { scope: { type: "default" } });  
    await api(env.BOT_TOKEN, "setMyCommands", { 
      commands: [
        { command: "start", description: "开始" },
        { command: "del", description: "撤回(需引用)" } 
      ], 
      scope: { type: "default" } 
    });  
    const admins = [...(env.ADMIN_IDS || "").split(/[,,]/), ...(await getJsonCfg("authorized_admins", env))];  
    const uniqueAdmins = [...new Set(admins.map(i => i.toString().trim()).filter(Boolean))];  
    for (const id of uniqueAdmins) {  
      await api(env.BOT_TOKEN, "setMyCommands", {  
        commands: [
          { command: "start", description: "面板" }, 
          { command: "del", description: "双向撤回" }, 
          { command: "help", description: "帮助" }, 
          { command: "reset", description: "重置用户验证" }
        ],  
        scope: { type: "chat", chat_id: id }  
      });  
    }  
  } catch {}  
}  
  
// --- 19. 回调处理 ---  
async function handleCallback(cb, env) {  
  const { data, message: msg, from } = cb;  
  const [act, p1, p2] = (data || "").split(":");  
  
  if (act === "inbox" && p1 === "del") {  
    await api(env.BOT_TOKEN, "deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id }).catch(() => {});  
    if (p2) { const u = await getUser(p2, env); await updUser(p2, { user_info: { ...u.user_info, last_notify: 0 } }, env); }  
    return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "已处理" }).catch(() => {});  
  }  
  
  if (act === "note" && p1 === "set") {  
    await setCfg(`admin_state:${from.id}`, JSON.stringify({ action: "input_note", target: p2 }), env);  
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "⌨️ 请回复备注内容 (回复 /clear 清除):" });  
  }  
  
  if (act === "config") {  
    if (!(await isPrimaryAdmin(from.id, env))) return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});  
    await api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id }).catch(() => {});  
    const [, t, k, v] = (data || "").split(":");  
    return handleAdminConfig(msg.chat.id, msg.message_id, t, k, v, env);  
  }  
  
  if (msg.chat.id.toString() === env.ADMIN_GROUP_ID && ["block", "unblock"].includes(act)) {  
    if (!(await isAuthAdmin(from.id, env))) return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});  
    const isB = act === "block";  
    const uid = p1;  
    const u = await getUser(uid, env);  
    await updUser(uid, { is_blocked: isB, block_count: 0 }, env);  
    if (u.user_info.card_msg_id) {  
      api(env.BOT_TOKEN, "editMessageReplyMarkup", { chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.card_msg_id, reply_markup: getBtns(uid, isB) }).catch(() => {});  
    }  
    await manageBlacklist(env, u, { id: uid, first_name: u.user_info.name || "User", username: u.user_info.username }, isB);  
    api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: isB ? "已屏蔽" : "已解封" }).catch(() => {});  
  }  
  
  if (act === "pin_card") {  
    if (!(await isAuthAdmin(from.id, env))) return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});  
    api(env.BOT_TOKEN, "pinChatMessage", { chat_id: msg.chat.id, message_id: msg.message_id, message_thread_id: msg.message_thread_id }).catch(() => {});  
    api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "已置顶" }).catch(() => {});  
  }  
}  
  
// --- 20. 管理员回复 ---  
async function handleAdminReply(msg, env) {  
  if (!msg.message_thread_id || msg.from.is_bot || !(await isAuthAdmin(msg.from.id, env))) return;  
  
  const stateStr = await getCfg(`admin_state:${msg.from.id}`, env);  
  if (stateStr) {  
    const state = safeParse(stateStr);  
    if (state.action === "input_note") {  
      const u = await getUser(state.target, env);  
      u.user_info.note = msg.text === "/clear" || msg.text === "清除" ? "" : msg.text;  
      await updUser(state.target, { user_info: u.user_info }, env);  
      await setCfg(`admin_state:${msg.from.id}`, "", env);  
      if (u.topic_id && u.user_info.card_msg_id) {  
        const meta = getUMeta({ id: state.target, first_name: u.user_info.name, username: u.user_info.username }, u, u.user_info.join_date || Date.now() / 1000);  
        api(env.BOT_TOKEN, "editMessageText", {  
          chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.card_msg_id, text: meta.card, parse_mode: "HTML", reply_markup: getBtns(state.target, u.is_blocked)  
        }).catch(() => {});  
      }  
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "✅ 备注已更新" });  
    }  
  }  
  
  const uid = (await sql(env, "SELECT user_id FROM users WHERE topic_id = ?", msg.message_thread_id.toString(), "first"))?.user_id;  
  if (!uid) return;  
  
  let replyToIdInUser = null;  
  if (msg.reply_to_message) {  
    try {  
      const ref = await sql(env, "SELECT user_msg_id FROM msg_mapping WHERE admin_msg_id = ?",  
        [msg.reply_to_message.message_id.toString()], "first");  
      if (ref) replyToIdInUser = ref.user_msg_id;  
    } catch {}  
  }  
  
  try {  
    const sent = await api(env.BOT_TOKEN, "copyMessage", {  
      chat_id: uid,  
      from_chat_id: msg.chat.id,  
      message_id: msg.message_id,  
      reply_to_message_id: replyToIdInUser  
    });  
      
    if (sent && sent.message_id) {  
      await sql(env, "INSERT OR REPLACE INTO msg_mapping (user_id, user_msg_id, admin_msg_id, ts) VALUES (?, ?, ?, ?)",  
        [uid, sent.message_id.toString(), msg.message_id.toString(), Date.now()]);  
    }  
  } catch (e) {  
    api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "❌ 发送失败 (用户可能已停止Bot)" }).catch(() => {});  
  }  
}  
  
// --- 21. 面板 (已移除备份配置，增加就寝时间配置) ---  
async function handleAdminConfig(cid, mid, type, key, val, env) {  
  const render = (txt, kb) => api(env.BOT_TOKEN, mid ? "editMessageText" : "sendMessage", { chat_id: cid, message_id: mid, text: txt, parse_mode: "HTML", reply_markup: kb });  
  const back = { text: "🔙 返回", callback_data: "config:menu" };  
  
  try {  
    if (!type || type === "menu") {  
      if (!key) return render("⚙️ <b>控制面板</b>", {  
        inline_keyboard: [  
          [{ text: "📝 基础", callback_data: "config:menu:base" }, { text: "🤖 自动回复", callback_data: "config:menu:ar" }],  
          [{ text: "🚫 屏蔽词", callback_data: "config:menu:kw" }, { text: "🛠 过滤", callback_data: "config:menu:fl" }],  
          [{ text: "👮 协管", callback_data: "config:menu:auth" }, { text: "🌙 就寝时间", callback_data: "config:menu:sleep" }],  
        ]  
      });  
      if (key === "base") {  
        const mode = await getCfg("captcha_mode", env), captchaOn = await getBool("enable_verify", env), qaOn = await getBool("enable_qa_verify", env);  
        let statusText = "❌ 已关闭"; if (captchaOn) statusText = mode === "recaptcha" ? "Google" : "Cloudflare";  
        return render(`基础配置\n验证码模式: ${statusText}\n问题验证: ${qaOn ? "✅" : "❌"}`, {  
          inline_keyboard: [  
            [{ text: "欢迎语", callback_data: "config:edit:welcome_msg" }, { text: "问题", callback_data: "config:edit:verif_q" }, { text: "答案", callback_data: "config:edit:verif_a" }],  
            [{ text: `验证码模式: ${statusText} (点击切换)`, callback_data: `config:rotate_mode` }],  
            [{ text: `问题验证: ${qaOn ? "✅ 开启" : "❌ 关闭"}`, callback_data: `config:toggle:enable_qa_verify:${!qaOn}` }],  
            [back]  
          ]  
        });  
      }  
      if (key === "fl") return render("🛠 <b>过滤设置</b>", await getFilterKB(env));  
      if (["ar", "kw", "auth"].includes(key)) return render(`列表: ${key}`, await getListKB(key, env));  
      if (key === "bak") {  
        const uid = await getCfg("unread_topic_id", env), blk = await getCfg("blocked_topic_id", env);  
        return render(`🔔 <b>聚合与黑名单话题</b>\n未读话题: ${uid ? `✅ (${uid})` : "⏳"}\n黑名单话题: ${blk ? `✅ (${blk})` : "⏳"}`, {  
          inline_keyboard: [  
            [{ text: "重置聚合话题", callback_data: "config:cl:unread_topic_id" }, { text: "重置黑名单", callback_data: "config:cl:blocked_topic_id" }],  
            [back]  
          ]  
        });  
      }  
      if (key === "sleep") {  
        const on = await getBool("enable_sleep_mode", env);
        const start = await getCfg("sleep_start", env);
        const end = await getCfg("sleep_end", env);
        const msgText = await getCfg("sleep_msg", env);  
        return render(`🌙 <b>就寝时间设置</b>\n状态: ${on ? "✅ 自动启用" : "❌ 已关闭"}\n区间: <code>${start}</code> - <code>${end}</code>\n提示语: ${escapeHTML(msgText)}`, {  
          inline_keyboard: [  
            [{ text: `模式: ${on ? "✅ 开启中" : "❌ 已关闭"}`, callback_data: `config:toggle:enable_sleep_mode:${!on}` }],  
            [{ text: "开始时间", callback_data: "config:edit:sleep_start" }, { text: "结束时间", callback_data: "config:edit:sleep_end" }],
            [{ text: "✏️ 修改提示语", callback_data: "config:edit:sleep_msg" }],  
            [back]  
          ]  
        });  
      }  
    }  
    if (type === "toggle") {  
      await setCfg(key, val, env);  
      return key === "enable_sleep_mode" ? handleAdminConfig(cid, mid, "menu", "sleep", null, env) : key === "enable_qa_verify" ? handleAdminConfig(cid, mid, "menu", "base", null, env) : render("🛠 <b>过滤设置</b>", await getFilterKB(env));  
    }  
    if (type === "cl") {  
      await setCfg(key, key === "authorized_admins" ? "[]" : "", env);  
      return handleAdminConfig(cid, mid, "menu", key === "unread_topic_id" || key === "blocked_topic_id" ? "bak" : key === "authorized_admins" ? "auth" : "bak", null, env);  
    }  
    if (type === "del") {  
      const realK = key === "kw" ? "block_keywords" : key === "auth" ? "authorized_admins" : "keyword_responses";  
      let l = await getJsonCfg(realK, env);  
      l = (Array.isArray(l) ? l : []).filter(i => (i.id || i).toString() !== val);  
      await setCfg(realK, JSON.stringify(l), env);  
      return render(`列表: ${key}`, await getListKB(key, env));  
    }  
    if (type === "edit" || type === "add") {  
      await setCfg(`admin_state:${cid}`, JSON.stringify({ action: "input", key: key + (type === "add" ? "_add" : "") }), env);  
      let promptText = `请输入 ${key} 的值 (/cancel 取消):`;  
      if (key === "sleep_start" || key === "sleep_end") promptText = `请输入时间 (24小时制, 如 23:30) (/cancel 取消):`;
      if (key === "ar" && type === "add") promptText = `请输入自动回复规则,格式:\n<b>关键词===回复内容</b>\n\n例如:价格===请联系人工客服\n(/cancel 取消)`;  
      if (key === "welcome_msg") promptText = `请发送新的欢迎语 (/cancel 取消):\n\n• 支持 <b>文字</b> 或 <b>图片/视频/GIF</b>\n• 支持占位符: {name}\n• 直接发送媒体即可`;  
      return api(env.BOT_TOKEN, "editMessageText", { chat_id: cid, message_id: mid, text: promptText, parse_mode: "HTML" });  
    }  
    if (type === "rotate_mode") {  
      const currentMode = await getCfg("captcha_mode", env), isEnabled = await getBool("enable_verify", env);  
      let nextMode = "turnstile", nextEnable = "true", toast = "已切换: Cloudflare";  
      if (isEnabled) {  
        if (currentMode === "turnstile") { nextMode = "recaptcha"; toast = "已切换: Google"; }  
        else { nextEnable = "false"; nextMode = currentMode; toast = "验证已关闭"; }  
      }  
      await setCfg("captcha_mode", nextMode, env);  
      await setCfg("enable_verify", nextEnable, env);  
      return render(`基础配置已更新\n${toast}`, { inline_keyboard: [[back]] });  
    }  
  } catch (e) { console.error("handleAdminConfig error:", e); }  
}  
  
async function getFilterKB(env) {  
  const s = async k => ((await getBool(k, env)) ? "✅" : "❌");  
  const b = (t, k, v) => ({ text: `${t} ${v}`, callback_data: `config:toggle:${k}:${v === "❌"}` });  
  const keys = ["enable_forward_forwarding", "enable_image_forwarding", "enable_audio_forwarding", "enable_sticker_forwarding", "enable_link_forwarding", "enable_channel_forwarding", "enable_text_forwarding"];  
  const vals = await Promise.all(keys.map(k => s(k)));  
  return { inline_keyboard: [[b("转发", keys[0], vals[0])], [b("媒体", keys[1], vals[1]), b("语音", keys[2], vals[2])], [b("贴纸", keys[3], vals[3]), b("链接", keys[4], vals[4])], [b("频道", keys[5], vals[5]), b("文本", keys[6], vals[6])], [{ text: "🔙 返回", callback_data: "config:menu" }]] };  
}  
  
async function getListKB(type, env) {  
  const k = type === "ar" ? "keyword_responses" : type === "kw" ? "block_keywords" : "authorized_admins";  
  const l = await getJsonCfg(k, env);  
  const btns = (Array.isArray(l) ? l : []).map(i => [{ text: `🗑 ${type === "ar" ? i.keywords : i}`, callback_data: `config:del:${type}:${i.id || i}` }]);  
  btns.push([{ text: "➕ 添加", callback_data: `config:add:${type}` }], [{ text: "🔙 返回", callback_data: "config:menu" }]);  
  return { inline_keyboard: btns };  
}  
  
async function handleAdminInput(id, msg, state, env) {  
  const txt = msg.text || "";  
  if (txt === "/cancel") {  
    await sql(env, "DELETE FROM config WHERE key=?", `admin_state:${id}`);  
    return handleAdminConfig(id, null, "menu", null, null, env);  
  }  
  let k = state.key, val = txt;  
  try {  
    if (k === "welcome_msg") {  
      if (msg.photo || msg.video || msg.animation) {  
        let fileId, type;  
        if (msg.photo) { type = "photo"; fileId = msg.photo[msg.photo.length - 1].file_id; }  
        else if (msg.video) { type = "video"; fileId = msg.video.file_id; }  
        else if (msg.animation) { type = "animation"; fileId = msg.animation.file_id; }  
        val = JSON.stringify({ type: type, file_id: fileId, caption: msg.caption || "" });  
      } else { val = txt; }  
    } else if (k.endsWith("_add")) {  
      k = k.replace("_add", "");  
      const realK = k === "ar" ? "keyword_responses" : k === "kw" ? "block_keywords" : "authorized_admins";  
      const list = await getJsonCfg(realK, env);  
      const arr = Array.isArray(list) ? list : [];  
      if (k === "ar") {  
        const [kk, rr] = txt.split("===");  
        if (kk && rr) arr.push({ keywords: kk, response: rr, id: Date.now() });  
        else return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 格式错误,请使用:关键词===回复内容" });  
      } else arr.push(txt);  
      val = JSON.stringify(arr);  
      k = realK;  
    } else if (k === "authorized_admins") {  
      val = JSON.stringify(txt.split(/[,,]/).map(s => s.trim()).filter(Boolean));  
    }  
    await setCfg(k, val, env);  
    await sql(env, "DELETE FROM config WHERE key=?", `admin_state:${id}`);  
    const displayVal = val.startsWith("{") && k === "welcome_msg" ? "[媒体配置]" : val.substring(0, 100);  
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `✅ ${k} 已更新:\n${displayVal}` }).catch(() => {});  
    await handleAdminConfig(id, null, "menu", null, null, env);  
  } catch (e) {  
    api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `❌ 失败: ${e.message}` }).catch(() => {});  
  }  
}  
  
async function handleDeleteSync(msg, env) {  
  const replyTo = msg.reply_to_message;  
  const chatId = msg.chat.id.toString();  
  const isAdminGroup = chatId === env.ADMIN_GROUP_ID;  
  
  let mapping;  
  if (isAdminGroup) {  
    mapping = await sql(env, "SELECT * FROM msg_mapping WHERE admin_msg_id = ?", [replyTo.message_id.toString()], "first");  
  } else {  
    mapping = await sql(env, "SELECT * FROM msg_mapping WHERE user_id = ? AND user_msg_id = ?", [chatId, replyTo.message_id.toString()], "first");  
  }  
  
  if (mapping) {  
    try {  
      await api(env.BOT_TOKEN, "deleteMessage", { chat_id: mapping.user_id, message_id: mapping.user_msg_id }).catch(() => {});  
      await api(env.BOT_TOKEN, "deleteMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: mapping.admin_msg_id }).catch(() => {});  
      await api(env.BOT_TOKEN, "deleteMessage", { chat_id: chatId, message_id: msg.message_id }).catch(() => {});  
    } catch (e) {  
      console.error("Delete Error:", e);  
    }  
  }  
}  
  
async function handleEditSync(msg, env) {  
  const mid = msg.message_id.toString();  
  const cid = msg.chat.id.toString();  
  const isAdmin = cid === env.ADMIN_GROUP_ID;  
    
  const mapping = isAdmin    
    ? await sql(env, "SELECT * FROM msg_mapping WHERE admin_msg_id = ?", [mid], "first")    
    : await sql(env, "SELECT * FROM msg_mapping WHERE user_id = ? AND user_msg_id = ?", [cid, mid], "first");    
    
  if (!mapping) return;    
    
  const targetChat = isAdmin ? mapping.user_id : env.ADMIN_GROUP_ID;    
  const targetMsg = isAdmin ? mapping.user_msg_id : mapping.admin_msg_id;    
  const content = msg.text || msg.caption || "";    
    
  try {    
    await api(env.BOT_TOKEN, msg.text ? "editMessageText" : "editMessageCaption", {    
      chat_id: targetChat, message_id: targetMsg,    
      [msg.text ? "text" : "caption"]: content + (isAdmin ? "" : "\n\n(📝 用户已修改内容)")    
    });    
  } catch {}    
}
