// ===== 情绪气象台 · 清除我的数据（④ 用户删除权）=====
// 调用：POST /functions/v1/erase-data  body: { "ticket":"...", "device_id":"..." }
// 用会话票据鉴权：删除该设备在此密钥下的绑定记录（用户数据足迹）。
// 作答/结果在浏览器本地计算、未上传，故可删除的用户数据即设备绑定记录。

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
function b64urlDecode(s: string): string {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
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

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });
  if (origin && !origin.endsWith(".github.io")) {
    return respond(origin, 403, { ok: false, code: "forbidden" });
  }

  let ticket = "", deviceId = "";
  try {
    const body = await req.json();
    ticket = String(body.ticket || "").trim().slice(0, 512);
    deviceId = String(body.device_id || "").trim().slice(0, 64);
  } catch {
    return respond(origin, 400, { ok: false, code: "bad_body" });
  }

  const tk = await verifyTicket(ticket);
  if (!tk) {
    return respond(origin, 401, { ok: false, code: "invalid_ticket", message: "会话已失效，请重新登录后再试" });
  }
  if (!deviceId || (tk.d && tk.d !== deviceId)) {
    return respond(origin, 400, { ok: false, code: "bad_device", message: "设备标识缺失或不匹配" });
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } },
  );

  try {
    // 删除该设备在此密钥下的绑定记录（用户唯一可归属的数据）
    const { error, count } = await supabase
      .from("license_devices")
      .delete({ count: "exact" })
      .eq("key_hash", tk.k)
      .eq("device_id", deviceId);
    if (error) return respond(origin, 500, { ok: false, code: "server" });
    return respond(origin, 200, { ok: true, deleted: count ?? 0, message: "已清除本设备的测评数据" });
  } catch {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
