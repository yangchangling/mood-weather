// ===== 情绪气象台 · 结果落库 + 相似人群 + 邀请返现 Edge Function =====
// 调用：POST /functions/v1/submit-result
//   body: { "identity":"程序员", "temp":26, "result_key":"sun", "inv":"<分享者key_hash,可选>", "ticket":"...", "device_id":"..." }
// 返回：{ ok:true, similar:{count,temp_min,temp_max,top_identity,top_result}, rewarded:boolean|undefined }
// 职责：
//   ① 验票据 + 设备绑定 + 会话期复查密钥（与 get-questions 同款鉴权）
//   ② 把测评结果匿名写入 mood_results（identity/temp/result_label）
//   ③ 若带 inv（分享者 key_hash）：为分享者记一条邀请并返 1 元站内券（防刷：不可邀请自己、同一对被邀请者仅一次）
//   ④ 按温度相近（|Δ|≤3）聚合返回匿名"相似人群"

import { createClient } from "jsr:@supabase/supabase-js@2";

const ALLOWED_ORIGIN_SUFFIX = ".github.io";

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
function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): string {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  return decodeURIComponent(escape(atob(t)));
}
async function hmacHex(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function verifyTicket(t: string): Promise<{ k: string; d: string; e: number } | null> {
  const parts = (t || "").split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expect = await hmacHex(Deno.env.get("SESSION_SECRET") ?? "", payload);
  if (sig !== expect) return null;
  try {
    const obj = JSON.parse(b64urlDecode(payload));
    if (!obj.k || typeof obj.e !== "number" || obj.e < Date.now()) return null;
    return { k: String(obj.k), d: String(obj.d || ""), e: obj.e };
  } catch {
    return null;
  }
}
const VALID_RESULTS = ["sun", "sky", "mist", "rain", "storm", "rainbow", "snow"];
const REWARD_CENTS = 100; // 1 元（分）

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });
  if (origin && !origin.endsWith(ALLOWED_ORIGIN_SUFFIX)) {
    return respond(origin, 403, { ok: false, code: "forbidden" });
  }

  try {
    let ticket = "", deviceId = "", identity = "", inv = "";
    let temp = 0, resultKey = "";
    try {
      const body = await req.json();
      ticket = String(body.ticket || "").trim().slice(0, 512);
      deviceId = String(body.device_id || "").trim().slice(0, 64);
      identity = String(body.identity || "").trim().slice(0, 20).replace(/[\x00-\x1F\x7F"]/g, "");
      inv = String(body.inv || "").trim().slice(0, 64);
      temp = Math.round(Number(body.temp));
      resultKey = String(body.result_key || "").trim().slice(0, 20);
    } catch {
      return respond(origin, 400, { ok: false, code: "bad_body" });
    }
    if (!ticket) return respond(origin, 400, { ok: false, code: "no_ticket" });
    if (!identity || temp < -30 || temp > 60) return respond(origin, 400, { ok: false, code: "bad_data" });
    if (VALID_RESULTS.indexOf(resultKey) < 0) resultKey = "sky";

    // ===== ① 票据鉴权 + 设备绑定 =====
    const tk = await verifyTicket(ticket);
    if (!tk) return respond(origin, 401, { ok: false, code: "invalid_key", message: "会话已失效，请重新输入测评密钥" });
    if (deviceId && tk.d && deviceId !== tk.d) {
      return respond(origin, 401, { ok: false, code: "invalid_key", message: "设备不匹配，请重新登录" });
    }
    const kh = tk.k;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { persistSession: false } },
    );

    // ===== 会话期复查密钥状态（被停用/过期则拒绝落库） =====
    const { data: licRow, error: licErr } = await supabase
      .from("license_keys").select("key_hash,status,expires_at").eq("key_hash", kh).maybeSingle();
    if (licErr) return respond(origin, 500, { ok: false, code: "server" });
    if (!licRow || licRow.status === "disabled") {
      return respond(origin, 200, { ok: false, code: "invalid_key", message: "密钥已失效/未登录，请重新输入密钥" });
    }
    if (licRow.expires_at && new Date(licRow.expires_at).getTime() < Date.now()) {
      return respond(origin, 200, { ok: false, code: "invalid_key", message: "密钥已过期，请重新购买" });
    }

    // ===== ② 结果匿名落库 =====
    await supabase.from("mood_results").insert({
      key_hash: kh, device_id: deviceId || "anon",
      identity_label: identity, temp, result_label: resultKey,
    }).then(() => {}, () => {});

    // ===== ③ 邀请返现：好友完成评测，给分享者返 1 元站内券 =====
    let rewarded = false;
    if (inv && inv !== kh && inv.length > 8) {
      // 防刷：同一对被邀请者(分享者,好友)仅记一次；分享者不能邀请自己
      const { data: dup } = await supabase
        .from("invitations").select("id").eq("inviter_key_hash", inv).eq("invitee_key_hash", kh).maybeSingle();
      if (!dup) {
        const { error: insErr } = await supabase.from("invitations").insert({
          inviter_key_hash: inv, invitee_key_hash: kh, status: "pending", reward_cents: REWARD_CENTS,
        });
        if (!insErr) {
          // 分享者余额 +1 元，邀请状态置 rewarded
          const { data: bal } = await supabase
            .from("coupon_balance").select("balance_cents").eq("key_hash", inv).maybeSingle();
          const cur = (bal && typeof bal.balance_cents === "number") ? bal.balance_cents : 0;
          await supabase.from("coupon_balance").upsert({
            key_hash: inv, balance_cents: cur + REWARD_CENTS, updated_at: new Date().toISOString(),
          }).then(() => {}, () => {});
          await supabase.from("invitations")
            .update({ status: "rewarded" })
            .eq("inviter_key_hash", inv).eq("invitee_key_hash", kh).then(() => {}, () => {});
          rewarded = true;
        }
      }
    }

    // ===== ④ 相似人群聚合（匿名，按温度相近） =====
    const { data: sim } = await supabase.rpc("mood_similar", { p_temp: temp, p_window: 3 });
    let similar: Record<string, unknown> | null = null;
    if (sim) {
      const s = (typeof sim === "string") ? JSON.parse(sim) : sim;
      similar = {
        count: Math.max(0, (Number(s.count) || 0) - 1), // 排除自己
        temp_min: s.temp_min,
        temp_max: s.temp_max,
        top_identity: s.top_identity,
        top_result: s.top_result,
      };
    }

    return respond(origin, 200, { ok: true, similar, rewarded: rewarded || undefined });
  } catch (err) {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
