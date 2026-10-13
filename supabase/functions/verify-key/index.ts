// ===== 情绪气象台 · 密钥校验 Edge Function =====
// 调用：POST /functions/v1/verify-key  body: { "key": "MOOD-XXXX-XXXX", "device_id": "..." }
// 返回：{ ok:true, first:boolean, ticket } 或 { ok:false, code:string }
// 安全加固：
//   S1 全局频控（防枚举碰撞）+ 单密钥连续失败锁定
//   S2 有效期校验 + 并发设备数上限
//   ① 密钥哈希化查找（库中不存明文）+ 签发短期会话票据（get-questions 改验票据）
//   ② 来源强校验（非白名单 Origin 拒绝）

import { createClient } from "jsr:@supabase/supabase-js@2";

const ALLOWED_ORIGIN_SUFFIX = ".github.io";
const TICKET_TTL_MS = 45 * 60 * 1000; // 会话票据有效期 45 分钟

function corsHeaders(origin: string): Record<string, string> {
  const allow = origin && origin.endsWith(ALLOWED_ORIGIN_SUFFIX) ? origin : "*";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Content-Type": "application/json",
  };
}
function respond(origin: string, status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders(origin) });
}
function cleanKey(s: string): string {
  return (s || "").trim().toUpperCase().replace(/\s+/g, "");
}
function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function hmacHex(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashKey(raw: string): Promise<string> {
  return hmacHex(Deno.env.get("HASH_SECRET") ?? "", "lic:" + cleanKey(raw));
}
async function issueTicket(keyHash: string, deviceId: string): Promise<string> {
  const payload = b64url(JSON.stringify({ k: keyHash, d: deviceId, e: Date.now() + TICKET_TTL_MS }));
  const sig = await hmacHex(Deno.env.get("SESSION_SECRET") ?? "", payload);
  return payload + "." + sig;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });
  // 来源强校验：浏览器请求若非白名单来源直接拒绝（服务端脚本攻击由票据+配额兜底）
  if (origin && !origin.endsWith(ALLOWED_ORIGIN_SUFFIX)) {
    return respond(origin, 403, { ok: false, code: "forbidden" });
  }

  try {
    let key = "", deviceId = "";
    try {
      const body = await req.json();
      key = cleanKey(body.key);
      deviceId = String(body.device_id || "").trim().slice(0, 64);
    } catch {
      return respond(origin, 400, { ok: false, code: "bad_body" });
    }
    if (!key) return respond(origin, 400, { ok: false, code: "no_key" });

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { persistSession: false } },
    );

    // ===== S1 全局频控：同一窗口内全局最多 300 次校验，防脚本枚举 =====
    const { data: gOk } = await supabase.rpc("ai_acquire", { p_bucket: "vkey-g", p_window_seconds: 60, p_max: 300 });
    if (gOk !== true) return respond(origin, 429, { ok: false, code: "rate_limited" });

    // 哈希化：库中只存 key_hash，这里按哈希查找
    const kh = await hashKey(key);

    // 单密钥失败锁定：10 分钟内最多失败 5 次，超限则拒绝
    async function markFailure(): Promise<boolean> {
      const r = await supabase.rpc("ai_acquire", { p_bucket: "vkey-fail:" + kh, p_window_seconds: 600, p_max: 5 });
      return r.data === true;
    }
    async function resetFailure(): Promise<void> {
      await supabase.from("ai_rate_limit").delete().eq("bucket", "vkey-fail:" + kh).then(undefined, () => {});
    }
    async function onFailure(code: string): Promise<Response> {
      const allowed = await markFailure();
      if (!allowed) return respond(origin, 429, { ok: false, code: "rate_limited" });
      return respond(origin, 200, { ok: false, code });
    }

    const { data: row, error } = await supabase
      .from("license_keys")
      .select("key_hash, status, expires_at, device_limit")
      .eq("key_hash", kh)
      .maybeSingle();
    if (error) return respond(origin, 500, { ok: false, code: "server" });
    if (!row) return onFailure("invalid");
    if (row.status === "disabled") return onFailure("disabled");
    // ===== 一码一用：已完成测评（status=used）的密钥拒绝再次登录（未完成前允许二次登录） =====
    if (row.status === "used") {
      return respond(origin, 200, { ok: false, code: "used", message: "该密钥已完成测评（一码一用），不可再次登录" });
    }
    // ===== S2 有效期校验 =====
    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return onFailure("expired");

    // ===== S2 设备上限：登记当前设备；超限则拒绝 =====
    if (deviceId) {
      const { data: dev } = await supabase.rpc("license_register_device", { p_key_hash: kh, p_device: deviceId });
      if (dev?.reason === "device_limit") {
        return respond(origin, 200, { ok: false, code: "device_limit", limit: dev.limit });
      }
      if (dev?.reason === "no_key") return respond(origin, 500, { ok: false, code: "server" });
    }

    // 一码一用判定改为「完成测试后才作废」：登录本身不消耗密钥。
    // 未完成测试（status 仍为 unused）允许同一密钥多次登录/继续；完成测试后 submit-result 会置为 used，届时此处拒绝二次登录。
    const first = row.status === "unused";

    await resetFailure(); // 校验成功，重置该密钥的失败计数

    // 签发短期会话票据（含 key_hash / device_id / 过期时间，HMAC 签名）；get-questions 改验票据
    const ticket = await issueTicket(kh, deviceId);
    // hash=key_hash：仅用于分享邀请定位（HMAC 哈希，非明文密钥、非认证凭证），前端据此生成邀请链接
    return respond(origin, 200, { ok: true, first, ticket, hash: kh });
  } catch (err) {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
