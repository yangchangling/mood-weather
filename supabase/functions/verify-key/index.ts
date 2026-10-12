// ===== 情绪气象台 · 密钥校验 Edge Function =====
// 调用：POST /functions/v1/verify-key  body: { "key": "MOOD-XXXX-XXXX" }
// 返回：{ ok:true, first:boolean } 或 { ok:false, code:string }

import { createClient } from "jsr:@supabase/supabase-js@2";

const ALLOWED_ORIGIN_SUFFIX = ".github.io"; // 仅放行 GitHub Pages；正式上线可改为自定义域名

function corsHeaders(origin: string): Record<string, string> {
  const allow =
    origin && origin.endsWith(ALLOWED_ORIGIN_SUFFIX) ? origin : "*";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers":
      "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Content-Type": "application/json",
  };
}

function respond(origin: string, status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders(origin),
  });
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders(origin) });
  }
  if (req.method !== "POST") {
    return respond(origin, 405, { ok: false, code: "method" });
  }

  try {
    let key = "";
    try {
      const body = await req.json();
      key = String(body.key || "")
        .trim()
        .toUpperCase()
        .replace(/\s+/g, "");
    } catch {
      return respond(origin, 400, { ok: false, code: "bad_body" });
    }
    if (!key) {
      return respond(origin, 400, { ok: false, code: "no_key" });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { persistSession: false } },
    );

    const { data: row, error } = await supabase
      .from("license_keys")
      .select("key, status")
      .eq("key", key)
      .maybeSingle();

    if (error) {
      return respond(origin, 500, { ok: false, code: "server" });
    }
    if (!row) {
      return respond(origin, 200, { ok: false, code: "invalid" });
    }
    if (row.status === "disabled") {
      return respond(origin, 200, { ok: false, code: "disabled" });
    }

    // 首次使用：unused → used（原子更新，带状态条件，防并发重复计数）
    let first = false;
    if (row.status === "unused") {
      const { error: upErr } = await supabase
        .from("license_keys")
        .update({ status: "used", used_at: new Date().toISOString() })
        .eq("key", key)
        .eq("status", "unused");
      if (upErr) {
        return respond(origin, 500, { ok: false, code: "server" });
      }
      first = true;
    }

    // used 的密钥仍放行（允许买家刷新 / 重测，不把人挡在门外），first=false
    return respond(origin, 200, { ok: true, first });
  } catch (err) {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
