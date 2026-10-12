// ===== 情绪气象台 · 用量/成本监控（S6）=====
// 调用：POST /functions/v1/monitor  body: { "admin_key":"..." }
// 返回成本相关可见性指标，供设置预算告警阈值；非公开，需 ADMIN_KEY。

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
  if (String(body.admin_key || "") !== (Deno.env.get("MANAGE_KEY_ADMIN") || "")) {
    return respond(origin, 401, { ok: false, code: "unauthorized" });
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } },
  );

  try {
    const [cache, cacheAi, cacheFallback, bank, lic, devices] = await Promise.all([
      supabase.from("question_cache").select("id", { count: "exact", head: true }),
      supabase.from("question_cache").select("id", { count: "exact", head: true }).eq("source", "ai"),
      supabase.from("question_cache").select("id", { count: "exact", head: true }).eq("source", "fallback"),
      supabase.from("question_bank").select("id", { count: "exact", head: true }),
      supabase.from("license_keys").select("id", { count: "exact", head: true }),
      supabase.from("license_devices").select("id", { count: "exact", head: true }),
    ]);
    // 最旧的 ai 缓存与最旧 fallback 缓存（判断是否需要清理）
    const [oldAi, oldFb] = await Promise.all([
      supabase.from("question_cache").select("created_at,last_hit_at,hit_count").eq("source", "ai").order("last_hit_at", { ascending: true }).limit(1),
      supabase.from("question_cache").select("created_at,last_hit_at").eq("source", "fallback").order("last_hit_at", { ascending: true }).limit(1),
    ]);
    return respond(origin, 200, {
      ok: true, metrics: {
        cache_total: cache.count ?? 0, cache_ai: cacheAi.count ?? 0, cache_fallback: cacheFallback.count ?? 0,
        bank_identities: bank.count ?? 0, keys_total: lic.count ?? 0, devices: devices.count ?? 0,
        oldest_ai_cache: oldAi?.data?.[0] || null,
        oldest_fallback_cache: oldFb?.data?.[0] || null,
        hint: "预算告警：请在 Supabase 项目设置(Spending limits)与 DeepSeek 开放平台设置月度预算/余额告警；建议每月核对 DeepSeek 用量。缓存清理可调用 cleanup_question_cache。",
      },
    });
  } catch {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
