/**    
* Telegram Bot Worker v3.85 (完整功能版：引用同步 + 撤回指令 + 编辑同步)  
*/  

const CACHE = {    
  data: {}, ts: 0, ttl: 60000, locks: new Set(),  
  admin: { ts: 0, ttl: 60000, primarySet: new Set(), authSet: new Set() },    
  cleanup: { processed_updates_ts: 0, ratelimits_ts: 0, messages_ts: 0, mapping_ts: 0 }    
};    

const DEFAULTS = {    
  welcome_msg: "欢迎 {name}！请发送消息开始咨询。",    
  enable_verify: "true", enable_qa_verify: "false", captcha_mode: "turnstile",  
  verif_q: "1+1=?", verif_a: "2", block_threshold: "5",    
  enable_image_forwarding: "true", enable_link_forwarding: "true", enable_text_forwarding: "true",    
  block_keywords: "[]", keyword_responses: "[]", authorized_admins: "[]"    
};    

const DELIVERED_REACTION = "👍";    

// --- 1. 核心入口 ---  
export default {  
  async fetch(req, env, ctx) {  
    ctx.waitUntil(dbInit(env).catch(e => console.error("DB Init Failed:", e)));  
    const url = new URL(req.url);  

    try {  
      if (req.method === "GET") {  
        if (url.pathname === "/verify") return handleVerifyPage(url, env);  
        return new Response("Bot v3.85 (System Running)", { status: 200 });  
      }  

      if (req.method === "POST") {  
        if (url.pathname === "/submit_token") return handleTokenSubmit(req, env, ctx);  
        if (!isTelegramWebhook(req, env)) return new Response("Forbidden", { status: 403 });  

        const update = await req.json();  
        // 幂等检查：防止重复处理
        const ok = await markUpdateOnce(update, env, ctx);  
        if (!ok) return new Response("OK");  

        ctx.waitUntil(handleUpdate(update, env, ctx));  
        return new Response("OK");  
      }  
    } catch (e) {  
      return new Response("Error", { status: 500 });  
    }  
    return new Response("Not Found", { status: 404 });  
  }  
};  

// --- 2. 消息分发 ---  
async function handleUpdate(update, env, ctx) {  
  const msg = update.message || update.edited_message;  
  if (!msg) return update.callback_query ? handleCallback(update.callback_query, env) : null;  

  // [功能] 撤回指令逻辑：回复任意消息并输入 /del
  if (msg.text === "/del" && msg.reply_to_message) {
    return handleDeleteSync(msg, env);
  }

  // [功能] 同步编辑消息  
  if (update.edited_message) {  
    return handleEditSync(update.edited_message, env);  
  }  

  // [功能] 消息路由  
  if (msg.chat.type === "private") {  
    await handlePrivate(msg, env, ctx);  
  } else if (msg.chat.id.toString() === env.ADMIN_GROUP_ID) {  
    await handleAdminReply(msg, env);  
  }  
}  

// --- 3. 核心功能：撤回同步 ---
async function handleDeleteSync(msg, env) {
  const replyTo = msg.reply_to_message;
  const chatId = msg.chat.id.toString();
  const isAdminGroup = chatId === env.ADMIN_GROUP_ID;

  // 根据当前环境，在数据库中查找对应的映射关系
  let mapping;
  if (isAdminGroup) {
    mapping = await sql(env, "SELECT * FROM msg_mapping WHERE admin_msg_id = ?", [replyTo.message_id.toString()], "first");
  } else {
    mapping = await sql(env, "SELECT * FROM msg_mapping WHERE user_id = ? AND user_msg_id = ?", [chatId, replyTo.message_id.toString()], "first");
  }

  if (mapping) {
    try {
      // 1. 删除用户私聊侧消息
      await api(env.BOT_TOKEN, "deleteMessage", { chat_id: mapping.user_id, message_id: mapping.user_msg_id }).catch(() => {});
      // 2. 删除管理群侧消息
      await api(env.BOT_TOKEN, "deleteMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: mapping.admin_msg_id }).catch(() => {});
      // 3. 删除发送 /del 的那条指令
      await api(env.BOT_TOKEN, "deleteMessage", { chat_id: chatId, message_id: msg.message_id }).catch(() => {});
    } catch (e) {
      console.error("Delete Error:", e);
    }
  }
}

// --- 4. 私聊逻辑 (含引用同步) ---  
async function handlePrivate(msg, env, ctx) {  
  const id = msg.chat.id.toString();  
  const u = await getUser(id, env);  
  
  if (u.is_blocked && !(await isAuthAdmin(id, env))) {  
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🚫 您已被屏蔽" }).catch(() => {});  
  }  
  
  const text = msg.text || "";  
  if (text.startsWith("/start")) return sendStart(id, msg, env);  
  
  // 验证逻辑 (此处演示默认为 verified，可根据需要开启验证流)
  if (u.user_state !== "verified" && !(await isAuthAdmin(id, env))) {  
    await updUser(id, { user_state: "verified" }, env);
  }  
  
  await handleVerifiedMsg(msg, u, env, ctx);  
}  

async function handleVerifiedMsg(msg, u, env, ctx) {  
  const id = u.user_id;  
  const text = msg.text || msg.caption || "";  
  
  // 敏感词拦截  
  const kws = safeParse(await getCfg("block_keywords", env), []);  
  if (text && kws.some(k => new RegExp(k, "gi").test(text))) {  
    const c = (u.block_count || 0) + 1;  
    await updUser(id, { block_count: c, is_blocked: c >= 5 }, env);  
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `⚠️ 请勿发送违禁词 (${c}/5)` });  
  }  
  
  // 转发至话题
  await relayToTopic(msg, u, env, ctx);  
}  

async function relayToTopic(msg, u, env, ctx) {  
  const uid = u.user_id;  
  let tid = u.topic_id;  
  
  if (!tid) {  
    try {  
      const name = (msg.from.first_name || "User") + " | " + uid;  
      const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: name.substring(0, 128) });  
      tid = t.message_thread_id.toString();  
      await updUser(uid, { topic_id: tid }, env);  
        
      const card = await api(env.BOT_TOKEN, "sendMessage", {  
        chat_id: env.ADMIN_GROUP_ID, message_thread_id: tid,  
        text: `<b>🪪 用户资料</b>\nID: <code>${uid}</code>\nName: ${msg.from.first_name || ""}`,  
        parse_mode: "HTML"  
      });  
      api(env.BOT_TOKEN, "pinChatMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: card.message_id }).catch(() => {});  
    } catch (e) {  
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙，请重发消息。" });  
    }  
  }  

  // [引用同步] 如果用户回复了机器人的消息，映射到管理群的原始引用
  let replyToIdInAdmin = null;
  if (msg.reply_to_message) {
    const ref = await sql(env, "SELECT admin_msg_id FROM msg_mapping WHERE user_id = ? AND user_msg_id = ?", 
                [uid, msg.reply_to_message.message_id.toString()], "first");
    if (ref) replyToIdInAdmin = ref.admin_msg_id;
  }
  
  try {  
    const relayed = await api(env.BOT_TOKEN, "copyMessage", {  
      chat_id: env.ADMIN_GROUP_ID, from_chat_id: uid,  
      message_id: msg.message_id, message_thread_id: tid,
      reply_to_message_id: replyToIdInAdmin
    });  
  
    if (relayed && relayed.message_id) {  
      await sql(env, "INSERT OR REPLACE INTO msg_mapping (user_id, user_msg_id, admin_msg_id, ts) VALUES (?, ?, ?, ?)",  
      [uid, msg.message_id.toString(), relayed.message_id.toString(), Date.now()]);  
    }  
  
    markDelivered(env, uid, msg.message_id);  
  } catch (e) {  
    if (e.message.includes("thread not found")) {  
      await updUser(uid, { topic_id: null }, env);
    }  
  }  
}  

// --- 5. 管理员回复逻辑 (含引用同步) ---  
async function handleAdminReply(msg, env) {  
  if (!msg.message_thread_id || msg.from.is_bot) return;  
  
  const row = await sql(env, "SELECT user_id FROM users WHERE topic_id = ?", [msg.message_thread_id.toString()], "first");  
  if (!row) return;  

  // [引用同步] 如果管理员回复了话题里的某条消息，映射到用户侧对应的消息
  let replyToIdInUser = null;
  if (msg.reply_to_message) {
    const ref = await sql(env, "SELECT user_msg_id FROM msg_mapping WHERE admin_msg_id = ?", 
                [msg.reply_to_message.message_id.toString()], "first");
    if (ref) replyToIdInUser = ref.user_msg_id;
  }
  
  try {  
    const sent = await api(env.BOT_TOKEN, "copyMessage", { 
      chat_id: row.user_id, 
      from_chat_id: msg.chat.id, 
      message_id: msg.message_id,
      reply_to_message_id: replyToIdInUser
    });  
    if (sent && sent.message_id) {  
      await sql(env, "INSERT OR REPLACE INTO msg_mapping (user_id, user_msg_id, admin_msg_id, ts) VALUES (?, ?, ?, ?)",  
      [row.user_id, sent.message_id.toString(), msg.message_id.toString(), Date.now()]);  
    }  
  } catch (e) {  
    api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "❌ 发送失败" });  
  }  
}  

// --- 6. 编辑同步逻辑 ---  
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

// --- 7. 数据库与工具函数 ---  
async function dbInit(env) {  
  await env.TG_BOT_DB.batch([  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, user_state TEXT DEFAULT 'new', is_blocked INTEGER DEFAULT 0, block_count INTEGER DEFAULT 0, topic_id TEXT, user_info_json TEXT DEFAULT '{}')`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS processed_updates (update_id TEXT PRIMARY KEY, ts INTEGER)`),  
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS msg_mapping (user_id TEXT, user_msg_id TEXT, admin_msg_id TEXT, ts INTEGER, PRIMARY KEY (user_id, user_msg_id))`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_msg ON msg_mapping (admin_msg_id)`)
  ]);  
}  

async function api(token, method, body) {  
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {  
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)  
  });  
  const d = await r.json();  
  if (!d.ok) throw new Error(d.description);  
  return d.result;  
}  

async function getUser(id, env) {  
  let u = await sql(env, "SELECT * FROM users WHERE user_id = ?", [id], "first");  
  if (!u) {  
    await tryRun(env, "INSERT OR IGNORE INTO users (user_id) VALUES (?)", [id]);  
    u = await sql(env, "SELECT * FROM users WHERE user_id = ?", [id], "first");  
  }  
  return u || { user_id: id, user_state: 'new' };  
}  

async function updUser(id, data, env) {  
  const keys = Object.keys(data);  
  const q = `UPDATE users SET ${keys.map(k => `${k}=?`).join(",")} WHERE user_id=?`;  
  await sql(env, q, [...keys.map(k => data[k]), id]);  
}  

async function getCfg(k, env) {  
  const row = await sql(env, "SELECT value FROM config WHERE key = ?", [k], "first");  
  return row ? row.value : (DEFAULTS[k] || "");  
}  

function isTelegramWebhook(req, env) {  
  return req.headers.get("X-Telegram-Bot-Api-Secret-Token") === env.TELEGRAM_WEBHOOK_SECRET;  
}  

const sql = async (env, query, args = [], type = "run") => {  
  const stmt = env.TG_BOT_DB.prepare(query).bind(...args);  
  return type === "run" ? await stmt.run() : await stmt[type]();  
};  

const tryRun = async (env, q, a) => { try { return await sql(env, q, a); } catch { return null; } };  
const safeParse = (s, f) => { try { return JSON.parse(s); } catch { return f; } };  

async function markUpdateOnce(update, env) {  
  const id = (update.update_id)?.toString();  
  if (!id) return true;  
  try {  
    await sql(env, "INSERT INTO processed_updates (update_id, ts) VALUES (?,?)", [id, Date.now()]);  
    return true;  
  } catch { return false; }  
}  

async function isAuthAdmin(id, env) {  
  const admins = (env.ADMIN_IDS || "").split(",");  
  return admins.includes(id.toString());  
}  

async function markDelivered(env, chatId, messageId) {  
  try {  
    await api(env.BOT_TOKEN, "setMessageReaction", {  
      chat_id: chatId, message_id: messageId,  
      reaction: [{ type: "emoji", emoji: DELIVERED_REACTION }]  
    });  
  } catch {}  
}  

async function sendStart(id, msg, env) {  
  await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: await getCfg("welcome_msg", env) });  
}  

function handleVerifyPage() { return new Response("Page OK"); }  
async function handleTokenSubmit() { return new Response(JSON.stringify({success:true})); }  
async function handleCallback() { return; }
