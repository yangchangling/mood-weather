// ===== 情绪气象台 · 密钥管理后台（S2 吊销/延期）=====
// 调用：POST /functions/v1/manage-key  body: { "admin_key":"...", "action":"...", "key":"..." }
// action: stats | list | disable | enable | extend | clear-expiry | list-devices | find-results | log-sale
// 仅持有 ADMIN_KEY 者可调用（env: MANAGE_KEY_ADMIN）
// 安全：按密钥哈希（HASH_SECRET）查找；列表仅返回脱敏 key_display，不透出明文。

import { createClient } from "jsr:@supabase/supabase-js@2";

function corsHeaders(origin: string): Record<string, string> {
  // 回显调用方 Origin：兼容 null(file://)、http://localhost(本地后台服务器)、*.github.io 等一切来源。
  // manage-key 的真正防线是 MANAGE_KEY_ADMIN 强鉴权（x-admin-key），来源校验对其为次要，故不在此设白名单。
  const allow = origin ? origin : "*";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-admin-key",
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
function randHex(n: number): string {
  const chars = "0123456789ABCDEF"; let s = "";
  for (let i = 0; i < n; i++) s += chars[Math.floor(Math.random() * 16)];
  return s;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });
  // 鉴权即来源防线：任何来源都放行 CORS（见 corsHeaders），真正授权由 MANAGE_KEY_ADMIN 强鉴权保证
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } },
  );

  // ---- 登录失败限流（暴力破解防护）----
  // 来源 IP（网关注入的 x-forwarded-for），做 HMAC 哈希后落库，不存明文 IP
  const rawIp = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "unknown";
  const ipHash = await hmacHex(Deno.env.get("HASH_SECRET") ?? "", "ip:" + rawIp);
  const win30 = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  const win15 = new Date(Date.now() - 15 * 60 * 1000).toISOString();

  // 全局维度：30 分钟窗口内失败总数超阈值 → 全局锁定（防分布式爆破）
  const { count: globalFail } = await supabase
    .from("admin_fail_log").select("id", { count: "exact", head: true })
    .gte("created_at", win30);
  if ((globalFail ?? 0) >= 200) return respond(origin, 429, { ok: false, code: "locked_global" });

  // IP 维度：15 分钟窗口内该 IP 失败超阈值 → 锁定该来源
  const { count: ipFail } = await supabase
    .from("admin_fail_log").select("id", { count: "exact", head: true })
    .eq("ip_hash", ipHash)
    .gte("created_at", win15);
  if ((ipFail ?? 0) >= 10) return respond(origin, 429, { ok: false, code: "locked_ip" });

  // 鉴权：ADMIN_KEY 经自定义 x-admin-key 头传递（不走 body，避免落入访问日志；Supabase 网关会拦截 Authorization 头做 JWT 校验，故不用 Bearer）
  const adminKey = (req.headers.get("x-admin-key") || "").trim();
  if (!adminKey || adminKey !== (Deno.env.get("MANAGE_KEY_ADMIN") || "")) {
    // 记录本次失败（用于限流窗口）；失败不重置，成功才清理
    await supabase.from("admin_fail_log").insert({ ip_hash: ipHash }).then(() => {});
    return respond(origin, 401, { ok: false, code: "unauthorized" });
  }
  // 鉴权成功：清除该来源的历史失败记录（解除限流）
  await supabase.from("admin_fail_log").delete().eq("ip_hash", ipHash);

  let body: any = {};
  try { body = await req.json(); } catch { return respond(origin, 400, { ok: false, code: "bad_body" }); }

  const action = String(body.action || "");
  const days = parseInt(body.days, 10);

  try {
    if (action === "stats") {
      const [lic, dev, cache, bank, used, disabled, unused, sold] = await Promise.all([
        supabase.from("license_keys").select("id", { count: "exact", head: true }),
        supabase.from("license_devices").select("id", { count: "exact", head: true }),
        supabase.from("question_cache").select("id", { count: "exact", head: true }),
        supabase.from("question_bank").select("id", { count: "exact", head: true }),
        supabase.from("license_keys").select("id", { count: "exact", head: true }).eq("status", "used"),
        supabase.from("license_keys").select("id", { count: "exact", head: true }).eq("status", "disabled"),
        supabase.from("license_keys").select("id", { count: "exact", head: true }).eq("status", "unused"),
        supabase.from("key_sales").select("id", { count: "exact", head: true }),
      ]);
      return respond(origin, 200, {
        ok: true, stats: {
          keys_total: lic.count ?? 0, keys_used: used.count ?? 0, keys_disabled: disabled.count ?? 0,
          keys_unused: unused.count ?? 0, sales_sold: sold.count ?? 0,
          devices: dev.count ?? 0, cache_rows: cache.count ?? 0, bank_identities: bank.count ?? 0,
        },
      });
    }

    // ===== 补货（A）：生成新密钥，明文仅在此响应返回给卖家一次，不落库 =====
    if (action === "gen") {
      const count = parseInt(body.count, 10);
      if (!Number.isFinite(count) || count < 1 || count > 50) return respond(origin, 400, { ok: false, code: "bad_count" });
      const added: { key: string; key_display: string }[] = [];
      let guard = 0;
      while (added.length < count && guard < 300) {
        guard++;
        const plain = "MOOD-" + randHex(4) + "-" + randHex(4);
        const h = await hashKey(plain);
        const { data: exist } = await supabase.from("license_keys").select("id").eq("key_hash", h).maybeSingle();
        if (exist) continue;
        const display = plain.slice(0, 5) + "••••" + plain.slice(-5);
        const { error } = await supabase.from("license_keys").insert({ key_hash: h, key_display: display, status: "unused", device_limit: 1 });
        if (error) return respond(origin, 500, { ok: false, code: "server" });
        added.push({ key: plain, key_display: display });
      }
      return respond(origin, 200, { ok: true, count: added.length, keys: added });
    }

    if (action === "list") {
      const { data } = await supabase
        .from("license_keys")
        .select("key_hash,key_display,status,expires_at,used_at,device_limit")
        .order("created_at", { ascending: false })
        .limit(200);
      return respond(origin, 200, { ok: true, keys: (data || []).map((r) => ({ ...r, key: r.key_display })) });
    }

    // 其余动作均需密钥：优先用 key_hash 直接定位，否则用明文哈希定位
    const keyHashParam = String(body.key_hash || "").trim();
    const key = String(body.key || "").trim();
    if (!keyHashParam && !key) return respond(origin, 400, { ok: false, code: "no_key" });
    const kh = keyHashParam || await hashKey(key);

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

    // ===== 按密钥查近期结果码（B）：输入密钥明文，返回该密钥近 30 天消费产生的结果（含 result_code，脱敏）=====
    // 用途：管理员查到结果码后复制发给用户，用户即可凭码二次进入查看结果。只返回摘要，不透出 device_id/key_hash/weather_json 全文。
    if (action === "find-results") {
      const { data: lic } = await supabase.from("license_keys").select("key_display").eq("key_hash", kh).maybeSingle();
      if (!lic) return respond(origin, 200, { ok: true, found: false, results: [] });
      const since = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
      const { data } = await supabase
        .from("mood_results")
        .select("identity_label,result_label,temp,result_code,created_at")
        .eq("key_hash", kh)
        .gte("created_at", since)
        .order("created_at", { ascending: false })
        .limit(1000); // 一码一用下每把密钥近30天最多1条；1000 仅为防异常数据膨胀的兜底，正常不会触发
      return respond(origin, 200, { ok: true, found: true, key_display: lic.key_display, since, results: data || [] });
    }

    // ===== 对账（C）：记录"哪把密钥发给了哪个订单"，台账只存脱敏标识，不含明文 =====
    if (action === "log-sale") {
      const orderNo = String(body.order_no || "").trim().slice(0, 64);
      const buyer = String(body.buyer || "").trim().slice(0, 64);
      if (!orderNo && !buyer) return respond(origin, 400, { ok: false, code: "no_order" });
      const { data: row } = await supabase.from("license_keys").select("key_display").eq("key_hash", kh).maybeSingle();
      if (!row) return respond(origin, 200, { ok: false, code: "invalid" });
      const { error } = await supabase.from("key_sales").insert({
        key_hash: kh, key_display: row.key_display, order_no: orderNo || null, buyer: buyer || null,
      });
      return respond(origin, error ? 500 : 200, error ? { ok: false, code: "server" } : { ok: true });
    }

    return respond(origin, 400, { ok: false, code: "unknown_action" });
  } catch {
    return respond(origin, 500, { ok: false, code: "server" });
  }
});
