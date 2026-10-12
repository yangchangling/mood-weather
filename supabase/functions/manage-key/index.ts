// ===== 情绪气象台 · 密钥管理后台（S2 吊销/延期）=====
// 调用：POST /functions/v1/manage-key  body: { "admin_key":"...", "action":"...", "key":"..." }
// action: stats | list | disable | enable | extend | list-devices
// 仅持有 ADMIN_KEY 者可调用（env: MANAGE_KEY_ADMIN）

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

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });

  let body: any = {};
  try { body = await req.json(); } catch { return respond(origin, 400, { ok: false, code: "bad_body" }); }

  // 鉴权：ADMIN_KEY 校验
  const adminKey = String(body.admin_key || "");
  if (!adminKey || adminKey !== (Deno.env.get("MANAGE_KEY_ADMIN") || "")) {
    return respond(origin, 401, { ok: false, code: "unauthorized" });
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } },
  );

  const action = String(body.action || "");
  const key = String(body.key || "").trim().toUpperCase().replace(/\s+/g, "");
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
        .select("key,status,expires_at,used_at,device_limit")
        .order("created_at", { ascending: false })
        .limit(200);
      return respond(origin, 200, { ok: true, keys: data || [] });
    }

    if (action === "list-devices") {
      if (!key) return respond(origin, 400, { ok: false, code: "no_key" });
      const { data } = await supabase.from("license_devices").select("device_id,first_seen,last_seen").eq("key", key);
      return respond(origin, 200, { ok: true, devices: data || [] });
    }

    if (!key) return respond(origin, 400, { ok: false, code: "no_key" });

    if (action === "disable") {
      const { error } = await supabase.from("license_keys").update({ status: "disabled" }).eq("key", key);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true });
    }
    if (action === "enable") {
      // 恢复为 used（已启用过）；如需 unused 可传 status
      const st = body.status === "unused" ? "unused" : "used";
      const { error } = await supabase.from("license_keys").update({ status: st }).eq("key", key);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true });
    }
    if (action === "extend") {
      if (!Number.isFinite(days) || days < 1) return respond(origin, 400, { ok: false, code: "bad_days" });
      const base = new Date();
      base.setDate(base.getDate() + days);
      const { error } = await supabase.from("license_keys").update({ expires_at: base.toISOString() }).eq("key", key);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true, expires_at: base.toISOString() });
    }
    if (action === "clear-expiry") {
      const { error } = await supabase.from("license_keys").update({ expires_at: null }).eq("key", key);
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true });
    }

    return respond(origin, 400, { ok: false, code: "unknown_action" });
  } catch {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
