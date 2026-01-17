/**
 * Telegram Bot Worker - 旗舰重构版
 * 功能：三模态验证、话题自动重置、全功能同步、就寝/限流/屏蔽词、控制面板
 */

const DEFAULTS = {
  welcome_msg: "欢迎 {name}! 请先完成验证以开始对话。",
  enable_verify: "true",
  enable_qa_verify: "true",
  captcha_mode: "turnstile", // turnstile, recaptcha, none
  verif_q: "1+1=?",
  verif_a: "2",
  block_threshold: "5",
  enable_sleep_mode: "false",
  sleep_start: "23:00",
  sleep_end: "07:00",
  sleep_msg: "当前是管理员就寝时间，消息已收到，我们会尽快回复。",
  block_keywords: "[]",
  keyword_responses: "[]"
};

const DELIVERED_REACTION = "👍";
const VERIFY_NONCE_TTL_MS = 15 * 60 * 1000;

export default {
  async fetch(req, env, ctx) {
    ctx.waitUntil(dbInit(env));
    const url = new URL(req.url);

    if (req.method === "GET") {
      if (url.pathname === "/verify") return handleVerifyPage(url, env);
      return new Response("Bot is running.");
    }

    if (req.method === "POST") {
      if (url.pathname === "/submit_token") return handleTokenSubmit(req, env, ctx);
      
      const secret = env.TELEGRAM_WEBHOOK_SECRET;
      if (secret && req.headers.get("X-Telegram-Bot-Api-Secret-Token") !== secret) {
        return new Response("Forbidden", { status: 403 });
      }

      const update = await req.json();
      ctx.waitUntil(handleUpdate(update, env, ctx));
      return new Response("OK");
    }
  }
};

// --- 数据库封装 ---
async function dbInit(env) {
  await env.TG_BOT_DB.batch([
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, user_state TEXT DEFAULT 'new', topic_id TEXT, is_blocked INTEGER DEFAULT 0, block_count INTEGER DEFAULT 0, user_info_json TEXT DEFAULT '{}')`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS msg_mapping (user_id TEXT, user_msg_id TEXT, admin_msg_id TEXT, ts INTEGER, PRIMARY KEY(user_id, user_msg_id))`)
  ]);
}

async function getCfg(k, env) {
  const row = await env.TG_BOT_DB.prepare("SELECT value FROM config WHERE key = ?").bind(k).first();
  return row ? row.value : (env[k.toUpperCase()] || DEFAULTS[k] || "");
}

async function setCfg(k, v, env) {
  await env.TG_BOT_DB.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").bind(k, v).run();
}

async function getUser(id, env) {
  let u = await env.TG_BOT_DB.prepare("SELECT * FROM users WHERE user_id = ?").bind(id.toString()).first();
  if (!u) {
    await env.TG_BOT_DB.prepare("INSERT OR IGNORE INTO users (user_id) VALUES (?)").bind(id.toString()).run();
    u = await env.TG_BOT_DB.prepare("SELECT * FROM users WHERE user_id = ?").bind(id.toString()).first();
  }
  u.is_blocked = !!u.is_blocked;
  u.user_info = JSON.parse(u.user_info_json || "{}");
  return u;
}

async function updUser(id, data, env) {
  if (data.user_info) {
    data.user_info_json = JSON.stringify(data.user_info);
    delete data.user_info;
  }
  const keys = Object.keys(data);
  const sets = keys.map(k => `${k}=?`).join(",");
  const vals = Object.values(data).map(v => typeof v === 'boolean' ? (v ? 1 : 0) : v);
  await env.TG_BOT_DB.prepare(`UPDATE users SET ${sets} WHERE user_id=?`).bind(...vals, id.toString()).run();
}

// --- 消息分发 ---
async function handleUpdate(update, env, ctx) {
  if (update.message_reaction) return handleReactionSync(update.message_reaction, env);

  const msg = update.message || update.edited_message;
  if (!msg) return update.callback_query ? handleCallback(update.callback_query, env) : null;

  // 双向撤回同步 [1]
  if (msg.text?.startsWith("/del") && msg.reply_to_message) return handleDeleteSync(msg, env);
  
  // 消息修改同步 [1]
  if (update.edited_message) return handleEditSync(update.edited_message, env);

  if (msg.chat.type === "private") {
    await handlePrivate(msg, env, ctx);
  } else if (msg.chat.id.toString() === env.ADMIN_GROUP_ID) {
    // 简化逻辑：群内回复即管理员 [1]
    await handleAdminReply(msg, env);
  }
}

// --- 私聊业务逻辑 ---
async function handlePrivate(msg, env, ctx) {
  const id = msg.chat.id.toString();
  const u = await getUser(id, env);
  
  if (u.is_blocked) {
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🚫 您已被封禁，无法发送消息。" });
  }

  // 基础限流 [1]
  if (!(await checkRateLimit(id, env))) return;

  // 验证流程拦截 [1][2]
  if (u.user_state !== "verified") {
    if (u.user_state === "pending_qa" && msg.text) return verifyQA(id, msg.text, env);
    return sendStart(msg, u, env);
  }

  if (msg.text === "/start") {
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "✅ 验证已通过，请直接发送消息。" });
  }

  // 就寝模式自动回复 [1][2]
  await checkSleepMode(id, u, env);

  await relayToTopic(msg, u, env);
}

// --- 转发核心 (含话题删除检测) ---
async function relayToTopic(msg, u, env) {
  const uid = u.user_id;
  let tid = u.topic_id;

  if (!tid) {
    // 创建新话题并发送资料卡 [1]
    const topicName = `${msg.from.first_name} | ${uid}`;
    try {
      const topic = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: topicName });
      tid = topic.message_thread_id.toString();
      await updUser(uid, { topic_id: tid }, env);
      
      const infoCard = `<b>🪪 用户资料卡</b>\n👤 姓名: <code>${msg.from.first_name}</code>\n🆔 ID: <code>${uid}</code>`;
      await api(env.BOT_TOKEN, "sendMessage", { 
        chat_id: env.ADMIN_GROUP_ID, 
        message_thread_id: tid, 
        text: infoCard, 
        parse_mode: "HTML",
        reply_markup: { inline_keyboard: [[{ text: "🚫 封禁用户", callback_data: `block:${uid}` }]] }
      });
    } catch (e) {
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙，请重试。" });
    }
  }

  try {
    const res = await api(env.BOT_TOKEN, "copyMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      from_chat_id: uid,
      message_id: msg.message_id,
      message_thread_id: tid
    });
    // 记录映射 [1]
    await env.TG_BOT_DB.prepare("INSERT OR REPLACE INTO msg_mapping (user_id, user_msg_id, admin_msg_id, ts) VALUES (?, ?, ?, ?)")
      .bind(uid, msg.message_id.toString(), res.message_id.toString(), Date.now()).run();
    
    // 成功回执 [1]
    api(env.BOT_TOKEN, "setMessageReaction", { chat_id: uid, message_id: msg.message_id, reaction: [{ type: "emoji", emoji: DELIVERED_REACTION }] });
  } catch (e) {
    // 话题删除处理：重置验证状态 [1]
    if (e.message.includes("thread not found") || e.message.includes("chat not found")) {
      await updUser(uid, { topic_id: null, user_state: "new" }, env);
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 之前的会话已被管理员删除，请重新进行人机验证。" });
    }
  }
}

// --- 管理员回复同步 ---
async function handleAdminReply(msg, env) {
  if (!msg.message_thread_id || msg.from.is_bot) return;
  
  // 根据话题 ID 反查用户
  const row = await env.TG_BOT_DB.prepare("SELECT user_id FROM users WHERE topic_id = ?").bind(msg.message_thread_id.toString()).first();
  if (!row) return;

  try {
    const res = await api(env.BOT_TOKEN, "copyMessage", {
      chat_id: row.user_id,
      from_chat_id: env.ADMIN_GROUP_ID,
      message_id: msg.message_id
    });
    // 记录映射以支持后续撤回/修改 [1]
    await env.TG_BOT_DB.prepare("INSERT OR REPLACE INTO msg_mapping (user_id, user_msg_id, admin_msg_id, ts) VALUES (?, ?, ?, ?)")
      .bind(row.user_id, res.message_id.toString(), msg.message_id.toString(), Date.now()).run();
  } catch (e) {
    api(env.BOT_TOKEN, "sendMessage", { chat_id: env.ADMIN_GROUP_ID, message_thread_id: msg.message_thread_id, text: "❌ 消息发送失败，用户可能已拉黑机器人。" });
  }
}

// --- 消息撤回同步 ---
async function handleDeleteSync(msg, env) {
  const replyTo = msg.reply_to_message;
  const isFromAdmin = msg.chat.id.toString() === env.ADMIN_GROUP_ID;
  
  const mapping = isFromAdmin
    ? await env.TG_BOT_DB.prepare("SELECT * FROM msg_mapping WHERE admin_msg_id = ?").bind(replyTo.message_id.toString()).first()
    : await env.TG_BOT_DB.prepare("SELECT * FROM msg_mapping WHERE user_id = ? AND user_msg_id = ?").bind(msg.chat.id.toString(), replyTo.message_id.toString()).first();

  if (mapping) {
    await api(env.BOT_TOKEN, "deleteMessage", { chat_id: mapping.user_id, message_id: mapping.user_msg_id }).catch(() => {});
    await api(env.BOT_TOKEN, "deleteMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: mapping.admin_msg_id }).catch(() => {});
    await api(env.BOT_TOKEN, "deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id }).catch(() => {});
  }
}

// --- 表态/表情同步 ---
async function handleReactionSync(reaction, env) {
  const isFromAdmin = reaction.chat.id.toString() === env.ADMIN_GROUP_ID;
  const mapping = isFromAdmin
    ? await env.TG_BOT_DB.prepare("SELECT * FROM msg_mapping WHERE admin_msg_id = ?").bind(reaction.message_id.toString()).first()
    : await env.TG_BOT_DB.prepare("SELECT * FROM msg_mapping WHERE user_id = ? AND user_msg_id = ?").bind(reaction.chat.id.toString(), reaction.message_id.toString()).first();

  if (mapping) {
    const targetChat = isFromAdmin ? mapping.user_id : env.ADMIN_GROUP_ID;
    const targetMsg = isFromAdmin ? mapping.user_msg_id : mapping.admin_msg_id;
    await api(env.BOT_TOKEN, "setMessageReaction", { chat_id: targetChat, message_id: targetMsg, reaction: reaction.new_reaction });
  }
}

// --- 控制面板触发 ---
async function handleAdminConfig(cid, mid, env) {
  const mode = await getCfg("captcha_mode", env);
  const kb = {
    inline_keyboard: [
      [{ text: `验证模式: ${mode}`, callback_data: "cfg:rotate_captcha" }],
      [{ text: "📝 修改就寝提示", callback_data: "cfg:edit_sleep_msg" }]
    ]
  };
  const text = "⚙️ <b>系统控制面板</b>\n设置已实时同步至数据库。";
  if (mid) await api(env.BOT_TOKEN, "editMessageText", { chat_id: cid, message_id: mid, text, parse_mode: "HTML", reply_markup: kb });
  else await api(env.BOT_TOKEN, "sendMessage", { chat_id: cid, text, parse_mode: "HTML", reply_markup: kb });
}

// --- 基础辅助工具 ---
async function api(token, method, body) {
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
  });
  const d = await r.json();
  if (!d.ok) throw new Error(d.description);
  return d.result;
}

// 频率限制
async function checkRateLimit(uid, env) {
  const now = Date.now();
  const key = `rl:${uid}:${Math.floor(now / 2000)}`;
  const res = await env.TG_BOT_DB.prepare("INSERT INTO config (key, value) VALUES (?, '1') ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1 RETURNING value").bind(key).first();
  return parseInt(res.value) <= 5;
}

// 就寝时间检查 [2]
async function checkSleepMode(id, u, env) {
  if ((await getCfg("enable_sleep_mode", env)) !== "true") return;
  const now = new Date();
  const time = now.toLocaleTimeString('zh-CN', { hour12: false, timeZone: 'Asia/Shanghai' }).slice(0, 5);
  const start = await getCfg("sleep_start", env);
  const end = await getCfg("sleep_end", env);
  const isSleeping = start <= end ? (time >= start && time <= end) : (time >= start || time <= end);
  
  if (isSleeping && (Date.now() - (u.user_info.last_sleep_ts || 0) > 300000)) {
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🌙 " + await getCfg("sleep_msg", env) });
    await updUser(id, { user_info: { ...u.user_info, last_sleep_ts: Date.now() } }, env);
  }
}
async function handleVerifyPage(url, env) {
  const uid = url.searchParams.get("user_id");
  const nonce = url.searchParams.get("nonce") || "";
  const mode = await getCfg("captcha_mode", env);
  
  // 根据模式选择 Site Key [1]
  const siteKey = mode === "recaptcha" ? env.RECAPTCHA_SITE_KEY : env.TURNSTILE_SITE_KEY;
  if (!uid || !siteKey) return new Response("Misconfigured: Missing UserID or SiteKey", { status: 400 });  

  // 选择加载的脚本 [1]
  const script = mode === "recaptcha" ? "https://www.google.com/recaptcha/api.js" : "https://challenges.cloudflare.com/turnstile/v0/api.js";
  const divClass = mode === "recaptcha" ? "g-recaptcha" : "cf-turnstile";  

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<script src="${script}" async defer></script>
<style>
  body{display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  #c{text-align:center;padding:25px;background:#f8f9fa;border-radius:15px;box-shadow:0 4px 15px rgba(0,0,0,0.1);max-width:90vw;width:300px}
  #m{margin-top:15px;font-weight:bold;color:#666}
</style></head>
<body>
<div id="c">
  <h3>🛡️ 安全验证</h3>
  <div class="${divClass}" data-sitekey="${siteKey}" data-callback="S"></div>
  <div id="m">等待验证...</div>
</div>
<script>
  const tg = window.Telegram.WebApp;
  tg.ready();
  tg.expand();
  const UI_USER_ID = '${escapeHTML(uid)}';
  const UI_NONCE = '${escapeHTML(nonce)}';

  function S(t){
    document.getElementById('m').innerText = '正在提交验证...';
    const initData = tg.initData || "";
    fetch('/submit_token', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: t, userId: UI_USER_ID, nonce: UI_NONCE, initData})
    })
    .then(r => r.json())
    .then(d => {
      if(d.success){ 
        document.getElementById('m').innerText = '✅ 验证成功！'; 
        document.getElementById('m').style.color = '#4caf50';
        setTimeout(() => { tg.close(); }, 1000); 
      } else { 
        document.getElementById('m').innerText = '❌ 验证失败，请刷新重试'; 
        document.getElementById('m').style.color = '#f44336';
      }
    })
    .catch(e => {
      document.getElementById('m').innerText = '⚠️ 网络错误';
      console.error(e);
    });
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

    // 1. 提交频率限制检查 [1]
    const rlPre = await checkSubmitRateLimit(req, env, ctx, "");
    if (!rlPre.allowed) throw new Error("Rate limited");  

    // 2. 校验 Telegram 的 initData 数据安全 [1]
    const parsed = await verifyTelegramInitData(initData, env.BOT_TOKEN, 600);
    const uid = parsed?.userId?.toString();
    if (!uid || (uiUserId && uiUserId !== uid)) throw new Error("UID mismatch or invalid data");  

    // 3. 用户封禁状态检查
    const u = await getUser(uid, env);
    if (u.is_blocked && !(await isAuthAdmin(uid, env))) throw new Error("Blocked");  

    // 4. Nonce (防重放) 校验 [1]
    const savedNonce = (u.user_info?.verify_nonce || "").toString();
    const savedTs = Number(u.user_info?.verify_nonce_ts || 0);
    const expired = !savedTs || Date.now() - savedTs > 15 * 60 * 1000; // 15分钟有效
    
    if (u.user_state !== "verified") {
      if (!nonce || !savedNonce || expired || nonce !== savedNonce) throw new Error("Nonce invalid");
      await updUser(uid, { user_info: { verify_nonce: "", verify_nonce_ts: 0 } }, env);
    }  

    // 5. 向服务端（Google 或 Cloudflare）发起二次验证 [1]
    const verifyUrl = mode === "recaptcha" ? "https://www.google.com/recaptcha/api/siteverify" : "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    const secretKey = mode === "recaptcha" ? env.RECAPTCHA_SECRET_KEY : env.TURNSTILE_SECRET_KEY;
    
    const params = mode === "recaptcha" ? new URLSearchParams({ secret: secretKey, response: token }) : JSON.stringify({ secret: secretKey, response: token });
    const headers = mode === "recaptcha" ? { "Content-Type": "application/x-www-form-urlencoded" } : { "Content-Type": "application/json" };  

    const r = await fetch(verifyUrl, { method: "POST", headers, body: params });
    const d = await r.json();
    if (!d.success) throw new Error("Captcha token invalid");  

    // 6. 更新用户验证状态 [1]
    const qaOn = await getBool("enable_qa_verify", env);
    if (qaOn) {
      await updUser(uid, { user_state: "pending_verification" }, env);
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 机器人验证通过！\n请继续回答以下问题：\n" + (await getCfg("verif_q", env)) });
    } else {
      await updUser(uid, { user_state: "verified" }, env);
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 验证通过！您现在可以发送消息联系管理员了。" });
    }
    
    return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
  } catch (e) {
    console.error("Submit Token Failed:", e.message);
    return new Response(JSON.stringify({ success: false, error: e.message }), { status: 400 });
  }
}
// 校验 Telegram 初始化数据 [1]
async function verifyTelegramInitData(initData, botToken, maxAgeSec) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  const authDate = parseInt(params.get("auth_date") || "0", 10);
  if (!hash || !authDate) throw new Error("Missing params");
  if (maxAgeSec && Math.floor(Date.now() / 1000) - authDate > maxAgeSec) throw new Error("Data expired");  

  const pairs = [];
  for (const [k, v] of params.entries()) {
    if (k !== "hash") pairs.push([k, v]);
  }
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join("\n");  

  const secretKey = await hmacSha256Bytes(new TextEncoder().encode("WebAppData"), new TextEncoder().encode(botToken));
  const calc = await hmacSha256Bytes(secretKey, new TextEncoder().encode(dataCheckString));
  
  if (bytesToHex(calc) !== hash) throw new Error("Signature mismatch");  

  let userObj = null;
  try { userObj = JSON.parse(params.get("user") || "{}"); } catch { }
  return { userId: userObj?.id, authDate, userObj };
}

// 辅助加密函数 [1]
async function hmacSha256Bytes(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}

function bytesToHex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
}
