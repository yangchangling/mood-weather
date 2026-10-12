// ===== 情绪气象台 · 单独同意留痕 Edge Function =====
// 调用：POST /functions/v1/record-consent  body: { "ticket": "...", "device_id": "...", "consent_version": "v1" }
// 返回：{ ok: true } 或 { ok:false, code }
// 目的（PIPL 合规③）：敏感个人信息需"单独同意"。用户在进入测评前点击"同意并继续"时，
// 本函数校验会话票据后，将 { key_hash, device_id, consent_version, created_at } 写入 consent_log，
// 作为"已取得单独同意"的自证留痕。best-effort：前端失败不阻断测评。

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
async function hmacHex(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function verifyTicket(t: string): Promise<{ k: string; d: string } | null> {
  const parts = (t || "").split(".");
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expect = await hmacHex(Deno.env.get("SESSION_SECRET") ?? "", payload);
  if (expect !== sig) return null;
  let obj: { k?: string; d?: string; e?: number };
  try {
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(b64 + "===".slice(0, (4 - (b64.length % 4)) % 4));
    obj = JSON.parse(json);
  } catch {
    return null;
  }
  if (!obj || !obj.k || !obj.e || obj.e < Date.now()) return null;
  return { k: obj.k, d: obj.d || "" };
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });
  if (origin && !origin.endsWith(ALLOWED_ORIGIN_SUFFIX)) {
    return respond(origin, 403, { ok: false, code: "forbidden" });
  }

  try {
    let ticket = "", deviceId = "", version = "";
    try {
      const body = await req.json();
      ticket = String(body.ticket || "");
      deviceId = String(body.device_id || "").trim().slice(0, 64);
      version = String(body.consent_version || "").trim().slice(0, 20);
    } catch {
      return respond(origin, 400, { ok: false, code: "bad_body" });
    }
    if (!ticket) return respond(origin, 400, { ok: false, code: "no_ticket" });
    if (!version) return respond(origin, 400, { ok: false, code: "no_version" });

    const info = await verifyTicket(ticket);
    if (!info) return respond(origin, 200, { ok: false, code: "invalid_ticket" });
    if (deviceId && info.d && deviceId !== info.d) {
      return respond(origin, 200, { ok: false, code: "device_mismatch" });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { persistSession: false } },
    );
    const { error } = await supabase.from("consent_log").insert({
      key_hash: info.k,
      device_id: info.d,
      consent_version: version,
    });
    if (error) return respond(origin, 500, { ok: false, code: "server" });
    return respond(origin, 200, { ok: true });
  } catch (err) {
    console.error("record-consent error:", err);
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
