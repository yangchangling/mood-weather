// ===== 情绪气象台 · 结果二次进入（只读）Edge Function =====
// 调用：POST /functions/v1/get-result
//   body: { "result_code":"R-XXXXXXXXXX" }
// 返回：{ ok:true, result:{ weather:{topKey,identity,temp,type}, identity, temp, result_label, created_at } }
//       { ok:false, code:"not_found" }
// 职责：凭强随机结果查询码（result_code）只读返回某次测评结果，用于"查看我的结果"二次进入。
//    - 与销售密钥独立：不消耗配额、不重新出题、不落新数据
//    - 任意设备凭码可查（码为强随机、不可枚举，天然充当访问凭证）
//    - 响应脱敏：不返回 key_hash / device_id
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

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });
  if (origin && !origin.endsWith(ALLOWED_ORIGIN_SUFFIX)) {
    return respond(origin, 403, { ok: false, code: "forbidden" });
  }

  try {
    let resultCode = "";
    try {
      const body = await req.json();
      resultCode = String(body.result_code || "").trim().toUpperCase().replace(/\s+/g, "");
    } catch {
      return respond(origin, 400, { ok: false, code: "bad_body" });
    }
    if (!/^R-[A-Z2-9]{6}$/.test(resultCode)) {
      return respond(origin, 400, { ok: false, code: "bad_code", message: "结果查询码格式不正确" });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { persistSession: false } },
    );

    const { data, error } = await supabase
      .from("mood_results")
      .select("identity_label,temp,result_label,weather_json,created_at")
      .eq("result_code", resultCode)
      .maybeSingle();
    if (error) return respond(origin, 500, { ok: false, code: "server" });
    if (!data) return respond(origin, 200, { ok: false, code: "not_found", message: "未找到该结果，请检查结果查询码" });

    // 脱敏返回：weather 快照 + 基础字段 + 创建时间（不含 key_hash / device_id）
    let weather = null;
    try {
      weather = data.weather_json;
    } catch {
      weather = null;
    }
    return respond(origin, 200, {
      ok: true,
      result: {
        weather: weather || { topKey: data.result_label, identity: data.identity_label, temp: data.temp },
        identity: data.identity_label,
        temp: data.temp,
        result_label: data.result_label,
        created_at: data.created_at,
      },
    });
  } catch {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
