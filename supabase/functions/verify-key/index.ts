// ===== 情绪气象台 · 密钥校验 Edge Function =====
// 调用：POST /functions/v1/verify-key  body: { "key": "MOOD-XXXX-XXXX", "device_id": "..." }
// 返回：{ ok:true, first:boolean } 或 { ok:false, code:string }
// 安全加固：
//   S1 全局频控（防枚举碰撞）+ 单密钥连续失败锁定
//   S2 有效期校验 + 并发设备数上限

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
function cleanKey(s: string): string {
  return (s || "").trim().toUpperCase().replace(/\s+/g, "");
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });

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

    // 单密钥失败锁定：10 分钟内最多失败 5 次，超限则拒绝
    async function markFailure(): Promise<boolean> {
      const r = await supabase.rpc("ai_acquire", { p_bucket: "vkey-fail:" + key, p_window_seconds: 600, p_max: 5 });
      return r.data === true; // true=仍在额度内(记录失败)；false=已锁定
    }
    async function resetFailure(): Promise<void> {
      await supabase.from("ai_rate_limit").delete().eq("bucket", "vkey-fail:" + key).then(undefined, () => {});
    }
    // 失败计数已超限 → 429
    async function onFailure(code: string): Promise<Response> {
      const allowed = await markFailure();
      if (!allowed) return respond(origin, 429, { ok: false, code: "rate_limited" });
      return respond(origin, 200, { ok: false, code });
    }

    const { data: row, error } = await supabase
      .from("license_keys")
      .select("key, status, expires_at, device_limit")
      .eq("key", key)
      .maybeSingle();
    if (error) return respond(origin, 500, { ok: false, code: "server" });
    if (!row) return onFailure("invalid");
    if (row.status === "disabled") return onFailure("disabled");
    // ===== S2 有效期校验 =====
    if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return onFailure("expired");

    // ===== S2 设备上限：登记当前设备；超限则拒绝 =====
    if (deviceId) {
      const { data: dev } = await supabase.rpc("license_register_device", { p_key: key, p_device: deviceId });
      if (dev?.reason === "device_limit") {
        return respond(origin, 200, { ok: false, code: "device_limit", limit: dev.limit });
      }
      if (dev?.reason === "no_key") return respond(origin, 500, { ok: false, code: "server" });
    }
    // 未带 device_id：放行但无法绑定设备（文档化的限制：脚本可绕过设备上限，主付费墙仍有效）

    // 首次使用：unused → used（原子更新，带状态条件，防并发重复计数）
    let first = false;
    if (row.status === "unused") {
      const { error: upErr } = await supabase
        .from("license_keys")
        .update({ status: "used", used_at: new Date().toISOString() })
        .eq("key", key)
        .eq("status", "unused");
      if (upErr) return respond(origin, 500, { ok: false, code: "server" });
      first = true;
    }

    await resetFailure(); // 校验成功，重置该密钥的失败计数
    return respond(origin, 200, { ok: true, first });
  } catch (err) {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
