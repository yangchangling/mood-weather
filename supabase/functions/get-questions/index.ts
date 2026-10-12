// ===== 情绪气象台 · 按身份取题（缓存优先 + DeepSeek 动态生成 + 兜底）=====
// 调用：POST /functions/v1/get-questions  body: { "identity": "程序员" }
// 返回：{ ok:true, cached:boolean, identity_label, questions:[...] }

const DEFAULT_BADGES = ["清晨", "上工", "白天", "傍晚", "睡前", "情绪来了", "与人相处", "收尾"];
const DIMS = ["sun", "sky", "mist", "rain", "storm", "rainbow", "snow"];

// 兜底通用题（AI 不可用时返回，保证永远能测；结构与前端固定题一致）
const FALLBACK_QUESTIONS = [
  { badge: "清晨", title: "闹钟响的那一下，你脑子里第一个念头是？", options: [
    { text: "又是元气满满的一天", w: { sun: 2, rainbow: 1 } },
    { text: "慢慢来，今天不急", w: { mist: 2, sky: 1 } },
    { text: "好困，今天大概不好过", w: { rain: 2, storm: 1 } },
    { text: "再睡五分钟，就五分钟", w: { snow: 2, mist: 1 } } ] },
  { badge: "上工", title: "出门赶路时，你更可能是哪种状态？", options: [
    { text: "把趣事先分享给朋友", w: { sun: 2, rainbow: 1 } },
    { text: "安静看自己感兴趣的内容", w: { mist: 1, snow: 1 } },
    { text: "莫名烦躁，只想快点到", w: { storm: 2, rain: 1 } },
    { text: "发呆，任思绪乱飘", w: { rain: 1, snow: 1 } } ] },
  { badge: "白天", title: "忙到一半，你最常偷偷处于哪种状态？", options: [
    { text: "想法一个接一个往外冒", w: { storm: 2, sun: 1 } },
    { text: "表面平静，心里自己嗨", w: { sky: 1, mist: 1 } },
    { text: "努力专注，偶尔走神", w: { snow: 1, rain: 1 } },
    { text: "脑子里在构想更好玩的画面", w: { rainbow: 2, storm: 1 } } ] },
  { badge: "傍晚", title: "一天结束前，你最想收到哪种消息？", options: [
    { text: "有人约我，热闹一下", w: { sun: 2, rainbow: 1 } },
    { text: "一句淡淡的关心就够", w: { mist: 2, rain: 1 } },
    { text: "一件有成就感的小事", w: { snow: 1, storm: 1 } },
    { text: "真诚的共鸣和认同", w: { rain: 1, rainbow: 1 } } ] },
  { badge: "睡前", title: "关灯前的几分钟，你通常会想什么？", options: [
    { text: "明天的事，有点小期待", w: { sun: 1, storm: 1 } },
    { text: "复盘今天，哪里能更好", w: { snow: 2, mist: 1 } },
    { text: "某些过去的人和事", w: { rain: 2, snow: 1 } },
    { text: "一些天马行空的念头", w: { rainbow: 2, storm: 1 } } ] },
  { badge: "情绪来了", title: "莫名低落时，你最容易靠什么缓过来？", options: [
    { text: "出门走走，让自己动起来", w: { sun: 2, storm: 1 } },
    { text: "一个人安静听点什么", w: { mist: 2, snow: 1 } },
    { text: "吃点暖的、好吃的", w: { rain: 1, rainbow: 1 } },
    { text: "找个人聊一聊", w: { sun: 1, rainbow: 1 } } ] },
  { badge: "与人相处", title: "你更习惯哪一种相处节奏？", options: [
    { text: "直接坦诚，越聊越热", w: { storm: 2, sun: 1 } },
    { text: "舒服自然，像天气一样温和", w: { sky: 2, mist: 1 } },
    { text: "需要一点空间慢慢靠近", w: { rain: 2, snow: 1 } },
    { text: "能一起笑闹，也能互相治愈", w: { rainbow: 2, sun: 1 } } ] },
  { badge: "收尾", title: "如果给自己的心情选一个天气，你会选？", options: [
    { text: "晴朗", w: { sun: 2 } }, { text: "通透", w: { sky: 2 } },
    { text: "平静", w: { mist: 2 } }, { text: "湿润", w: { rain: 2 } },
    { text: "热烈", w: { storm: 2 } }, { text: "绚烂", w: { rainbow: 2 } },
    { text: "清澈", w: { snow: 2 } } ] }
];

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
function normKey(s: string): string {
  return (s || "").toLowerCase().replace(/[\s\p{P}\p{S}]/gu, "");
}

// 校验题目结构与计分维度，保证可计分
function validate(q: any): boolean {
  if (!Array.isArray(q) || q.length !== 8) return false;
  for (let i = 0; i < 8; i++) {
    const item = q[i];
    if (!item || typeof item.title !== "string") return false;
    const expectOpts = i === 7 ? 7 : 4;
    if (!Array.isArray(item.options) || item.options.length !== expectOpts) return false;
    for (const o of item.options) {
      if (!o || typeof o.text !== "string" || typeof o.w !== "object" || !o.w) return false;
      const keys = Object.keys(o.w);
      if (!keys.length) return false;
      for (const k of keys) {
        if (!DIMS.includes(k) || !Number.isFinite(Number(o.w[k]))) return false;
      }
    }
  }
  return true;
}
function normalize(q: any[]): any[] {
  return q.map((item, i) => ({
    badge: typeof item.badge === "string" ? item.badge : DEFAULT_BADGES[i],
    title: item.title,
    options: item.options.map((o: any) => ({ text: o.text, w: o.w })),
  }));
}

async function callDeepSeek(label: string, temperature: number): Promise<any[]> {
  const sys = [
    "你是「情绪气象台」的出题引擎，为指定身份生成情境化心情测试题。",
    "要求：",
    "1. 共 8 题，前 7 题覆盖该身份真实一天的场景：清晨醒来、上工/通勤、白天忙碌、傍晚收工、深夜睡前、情绪低落时、与人相处；每题恰好 4 个选项。",
    "2. 题目和选项要高度贴合「" + label + "」的真实生活细节，让该身份的人一看就觉得「被说中」，语言像朋友说话、有画面感，4 个选项长度相近。",
    "3. 第 8 题是收尾天气直选，固定 7 个选项文字：晴朗、通透、平静、湿润、热烈、绚烂、清澈。",
    "4. 每个选项必须给字段 w：映射到 7 种天气维度的整数权重，主维度给 2、可给一个次维度 1。维度含义：",
    "sun=阳光有感染力行动派；sky=清醒稳定治愈；mist=温柔内敛高共情；rain=敏感细腻洞察力；storm=行动力强敢表达；rainbow=创造力乐观氛围制造；snow=冷静独立思考。",
    "5. 只输出 JSON，形如 {\"questions\":[{\"badge\":\"清晨\",\"title\":\"…\",\"options\":[{\"text\":\"…\",\"w\":{\"sun\":2}}]}]}，不要任何解释。",
  ].join("\n");

  const resp = await fetch("https://api.deepseek.com/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + (Deno.env.get("DEEPSEEK_API_KEY") || ""),
    },
    body: JSON.stringify({
      model: "deepseek-chat",
      response_format: { type: "json_object" },
      temperature,
      messages: [
        { role: "system", content: sys },
        { role: "user", content: "身份：" + label },
      ],
    }),
  });
  if (!resp.ok) throw new Error("deepseek http " + resp.status);
  const data = await resp.json();
  const content = data?.choices?.[0]?.message?.content;
  const parsed = JSON.parse(content);
  return parsed.questions;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });

  let label = "";
  try {
    const body = await req.json();
    label = String(body.identity || "").trim().slice(0, 20);
  } catch {
    return respond(origin, 400, { ok: false, code: "bad_body" });
  }
  if (!label) return respond(origin, 400, { ok: false, code: "no_identity" });

  const key = normKey(label);

  // 1) 连接数据库（service_role）
  const { createClient } = await import("jsr:@supabase/supabase-js@2");
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } },
  );

  // 2) 缓存命中
  const { data: hit } = await supabase
    .from("question_cache")
    .select("identity_label,questions")
    .eq("identity_key", key)
    .maybeSingle();
  if (hit?.questions) {
    await supabase.rpc("inc_hits", { p_key: key }).then(undefined, () => {});
    return respond(origin, 200, { ok: true, cached: true, identity_label: hit.identity_label, questions: hit.questions });
  }

  // 3) 未命中 → 调 DeepSeek（失败重试一次，降温）
  let questions: any[] | null = null;
  try {
    let raw = await callDeepSeek(label, 0.9);
    if (!validate(raw)) {
      raw = await callDeepSeek(label, 0.5);
    }
    if (validate(raw)) questions = normalize(raw);
  } catch { /* 继续兜底 */ }

  // 4) 成功则缓存 AI 题；失败则缓存兜底题（避免反复失败烧钱）
  const source = questions ? "ai" : "fallback";
  const finalQ = questions || FALLBACK_QUESTIONS;
  await supabase.from("question_cache").upsert({
    identity_key: key, identity_label: label, questions: finalQ, source,
  }, { onConflict: "identity_key" });

  return respond(origin, 200, { ok: true, cached: false, identity_label: label, questions: finalQ });
});
