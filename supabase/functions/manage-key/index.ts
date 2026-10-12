// ===== 情绪气象台 · 密钥管理后台（S2 吊销/延期）=====
// 调用：POST /functions/v1/manage-key  body: { "admin_key":"...", "action":"...", "key":"..." }
// action: stats | list | disable | enable | extend | clear-expiry | list-devices
// 仅持有 ADMIN_KEY 者可调用（env: MANAGE_KEY_ADMIN）
// 安全：按密钥哈希（HASH_SECRET）查找；列表仅返回脱敏 key_display，不透出明文。

import { createClient } from "jsr:@supabase/supabase-js@2";

function corsHeaders(origin: string): Record<string, string> {
  const allow = origin && origin.endsWith(".github.io") ? origin : "*";
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
async function hmacHex(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashKey(raw: string): Promise<string> {
  return hmacHex(Deno.env.get("HASH_SECRET") ?? "", "lic:" + cleanKey(raw));
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });
  if (origin && !origin.endsWith(".github.io")) {
    return respond(origin, 403, { ok: false, code: "forbidden" });
  }

  let body: any = {};
  try { body = await req.json(); } catch { return respond(origin, 400, { ok: false, code: "bad_body" }); }

  // 鉴权：ADMIN_KEY 经自定义 x-admin-key 头传递（不走 body，避免落入访问日志；Supabase 网关会拦截 Authorization 头做 JWT 校验，故不用 Bearer）
  const adminKey = (req.headers.get("x-admin-key") || "").trim();
  if (!adminKey || adminKey !== (Deno.env.get("MANAGE_KEY_ADMIN") || "")) {
    return respond(origin, 401, { ok: false, code: "unauthorized" });
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } },
  );

  const action = String(body.action || "");
  const days = parseInt(body.days, 10);

  try {
    if (action === "stats") {
      const [lic, dev, cache, bank, used, disabled] = await Promise.all([
        supabase.from("license_keys").select("id", { count: "exact", head: true }),
        supabase.from("license_devices").select("id", { count: "exact", head: true }),
        supabase.from("question_cache").select("id", { count: "exact", head: true }),
        supabase.from("question_bank").select("id", { count: "exact", head: true }),
        supabase.from("license_keys").select("id", { count: "exact", head: true }).eq("status", "used"),
        supabase.from("license_keys").select("id", { count: "exact", head: true }).eq("status", "disabled"),
      ]);
      return respond(origin, 200, {
        ok: true, stats: {
          keys_total: lic.count ?? 0, keys_used: used.count ?? 0, keys_disabled: disabled.count ?? 0,
          devices: dev.count ?? 0, cache_rows: cache.count ?? 0, bank_identities: bank.count ?? 0,
        },
      });
    }

    if (action === "list") {
      const { data } = await supabase
        .from("license_keys")
        .select("key_display,status,expires_at,used_at,device_limit")
        .order("created_at", { ascending: false })
        .limit(200);
      return respond(origin, 200, { ok: true, keys: (data || []).map((r) => ({ ...r, key: r.key_display })) });
    }

    // 其余动作均需密钥，先哈希化
    const key = String(body.key || "").trim();
    if (!key) return respond(origin, 400, { ok: false, code: "no_key" });
    const kh = await hashKey(key);

    if (action === "list-devices") {
      const { data } = await supabase.from("license_devices").select("device_id,first_seen,last_seen").eq("key_hash", kh);
      return respond(origin, 200, { ok: true, devices: data || [] });
    }

    if (action === "disable") {
      const { error } = await supabase.from("license_keys").update({ status: "disabled" }).eq("key_hash", kh);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true });
    }
    if (action === "enable") {
      const st = body.status === "unused" ? "unused" : "used";
      const { error } = await supabase.from("license_keys").update({ status: st }).eq("key_hash", kh);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true });
    }
    if (action === "extend") {
      if (!Number.isFinite(days) || days < 1) return respond(origin, 400, { ok: false, code: "bad_days" });
      const base = new Date();
      base.setDate(base.getDate() + days);
      const { error } = await supabase.from("license_keys").update({ expires_at: base.toISOString() }).eq("key_hash", kh);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true, expires_at: base.toISOString() });
    }
    if (action === "clear-expiry") {
      const { error } = await supabase.from("license_keys").update({ expires_at: null }).eq("key_hash", kh);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true });
    }

    return respond(origin, 400, { ok: false, code: "unknown_action" });
  } catch {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
