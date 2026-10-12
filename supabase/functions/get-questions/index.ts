// ===== 情绪气象台 · 按身份取题（缓存优先 + DeepSeek 动态生成 + 兜底）=====
// 调用：POST /functions/v1/get-questions  body: { "identity": "程序员" }
// 返回：{ ok:true, cached:boolean, identity_label, questions:[...] }

const DEFAULT_BADGES = ["清晨", "上工", "白天", "傍晚", "睡前", "情绪来了", "与人相处", "收尾"];
const SCENE_BADGES = ["清晨", "上工", "白天", "傍晚", "睡前", "情绪来了", "与人相处"];
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

// 敏感词（命中即视为非法身份，不做职业处理）
const ILLEGAL_PAT = /杀|砍|炸|枪|刀|血|尸|凶手|杀人|虐杀|自残|自杀|枪杀|凶器|爆炸|炸弹|恐怖|袭击|绑架|抢劫|强奸|杀人犯|刀具|武器|报复|殴|暴力|虐待|行凶|色情|性爱|性交|做爱|嫖|妓女|卖淫|黄色|淫|裸|裸体|春宫|情色|av|成人片|小姐|招嫖|援交|约炮|裸聊|艳照|淫秽|骚货|妓院|porn|sexy|fuck|sex|犯罪|违法|非法|走私|销赃|洗钱|诈骗|行贿|受贿|贿赂|伪造|造假|黑客|木马|越狱|逃税|漏税|黑产|刷单|翻墙|传销|赌博|赌场|赌球|毒品|吸毒|冰毒|海洛因|大麻|摇头丸|可卡因|鸦片|制毒|贩毒|嗑药|毒枭|毒贩|傻逼|你妈的|草泥马|尼玛|煞笔|狗屁|垃圾|贱|婊|贱人|贱货|泼妇|怨妇|骚|狐狸精|小三|二奶|破鞋|屌|逼|装逼|滚粗|去死|废物|弱智|白痴|脑残|sb|tmd|bitch|shit|台独|港独|疆独|藏独|法轮|反共|颠覆|分裂/i;
// 常见英文职业词（允许纯英文输入的职业，其余纯英文拦截）
const OK_EN = ["it","ui","ux","soho","sales","freelancer","barista","coder","designer","ceo","cfo","cto","pm","hr","boss","driver","waiter","worker","teacher","doctor","nurse","accountant","lawyer","engineer","artist","chef","blogger","vlogger","anchor","trader","agent"];

// 合法性校验：拦截敏感/非职业/纯符号输入，避免无效 AI 调用与脏数据
function isLegalIdentity(s: string): boolean {
  const v = (s || "").trim();
  if (!v || v.length > 20) return false;
  if (ILLEGAL_PAT.test(v)) return false;       // 敏感词
  if (/[\u4e00-\u9fa5]/.test(v)) return true;  // 含中文放行（是否真职业交给模糊匹配/生成）
  // 无中文：仅允许已知英文职业词
  const alnum = v.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (OK_EN.indexOf(alnum) >= 0) return true;
  // 含字母但非英文职业词 → 非法
  if (/[a-zA-Z]/.test(v)) return false;
  // 纯数字/符号 → 非法
  return false;
}

// 编辑距离（Levenshtein）——用于身份名模糊匹配
function editDist(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const dp: number[] = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    let prev = dp[0]; dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[n];
}

// 模糊匹配：输入与某已存在身份是否「沾边」。
// 优先级：字面精确 → 子串包含 → 语义别名 → 编辑距离近似。
// 阈值放得宽（宁准勿耗），杜绝「不沾边也复用」，最大限度避免浪费 AI 算力。
// 语义别名表：口语化称呼 → 正式身份（供 aliasResolve 使用）。已结合网络常见称呼维护，新增身份可按需补充。
const IDENTITY_ALIASES: Record<string, string[]> = {
  "程序员": ["码农", "程序猿", "程序媛", "码畜", "攻城狮", "开发", "开发者", "研发", "it", "it男", "it女",
              "程序员", "软件工程师", "软件开发", "写代码的", "搬砖码农", "代码狗", "技术男", "程序员大哥", "程序狗"],
  "骑手": ["送外卖的", "外卖员", "外卖骑手", "配送员", "网约配送员", "送快递的", "快递员", "快递小哥",
              "外卖小哥", "跑腿", "跑腿小哥", "骑手小哥", "蓝骑士", "同城配送", "快递师傅", "外卖", "闪送", "跑单的"],
  "医护": ["医生", "大夫", "护士", "白衣天使", "白衣战士", "白大褂", "医学生", "医务工作者", "医护人员",
              "提灯天使", "救死扶伤的", "大白", "白衣", "医疗工作者", "郎中", "医师", "白衣天使们"],
  "教师": ["老师", "教师", "人民教师", "教书匠", "园丁", "灵魂工程师", "大先生", "授课老师", "辅导老师",
              "先生", "教书先生", "教员", "夫子", "老师傅", "班主任", "教育工作者", "授业者", "桃李"],
  "学生": ["学生党", "大学生", "同学", "在校生", "考研党", "中学生", "小学生", "学生妹", "学生仔",
              "脆皮大学生", "吗喽", "学生娃", "读书人", "校园人", "同学仔", "小学鸡"],
  "公务员": ["体制内", "公职人员", "机关单位", "公务员", "事业单位", "铁饭碗", "考编的", "考碗族",
              "干部", "公家饭", "公务员考试", "体制人", "编制内", "人民公仆"],
  "销售": ["销售员", "业务员", "跑业务的", "销售顾问", "销售经理", "电销", "导购", "推销员", "销售代表",
              "销售助理", "卖货的", "业务代表", "跑街", "掮客", "sales", "salesman", "销售总监", "搞销售的"],
  "宝妈": ["全职妈妈", "宝妈", "全职太太", "新手妈妈", "带娃的", "家庭主妇", "家庭妇女", "全职妈妈们",
              "哺乳期妈妈", "宝妈宝爸", "带孩子的", "全职奶妈", "妈妈党", "全职妈咪", "二胎宝妈"],
  "设计师": ["设计", "ui设计师", "平面设计师", "美工", "插画师", "设计师", "设计狗", "画图的", "美工狗",
              "视觉设计", "设计狮", "电商美工", "美术师", "手艺人", "作图人", "设计民工", "画画的", "产品设计"],
  "自由职业": ["自由职业者", "自己创业", "个体户", "自由工作者", "soho", "soho族", "做自媒体的", "自媒体人",
              "数字游民", "自由职业人", "freelancer", "居家办公", "独立创作者", "自由撰稿人", "斜杠", "斜杠青年",
              "自由工作者们", "博主", "自由摄影", "接单的"],
  "打工人": ["打工人", "上班族", "社畜", "公司职员", "白领", "搬砖的", "打工的", "打工仔", "打工妹",
              "牛马", "天选打工人", "职场人", "坐办公室的", "上班的", "社畜打工人", "打工魂", "脆皮打工人"],
  "咖啡师": ["咖啡师", "咖啡店员", "咖啡店店员", "barista", "咖啡吧员", "咖啡师傅", "冲咖啡的", "做咖啡的",
              "吧台师", "咖啡技师", "咖啡专家", "咖啡服务生", "咖啡学徒", "咖啡师们"],
};

function aliasResolve(input: string): string {
  const a = normKey(input);
  if (!a) return "";
  for (const [identity, aliases] of Object.entries(IDENTITY_ALIASES)) {
    for (const al of aliases) {
      const na = normKey(al);
      if (na && (a === na || a.includes(na) || na.includes(a))) return identity;
    }
  }
  return "";
}

function fuzzyMatch(input: string, existing: string): boolean {
  const a = normKey(input), b = normKey(existing);
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.includes(b) || b.includes(a)) return true; // 子串包含，如「咖啡师店员」→「咖啡师」
  if (aliasResolve(input) === normKey(existing) || normKey(aliasResolve(input)) === b) return true; // 语义别名
  if (editDist(a, b) <= 2) return true;              // 近似，如「咖啡师」「咖非师」
  return false;
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

// 单题合法性（题库池里的题也要校验）
function validSingle(item: any): boolean {
  if (!item || typeof item.title !== "string") return false;
  if (!Array.isArray(item.options) || item.options.length !== 4) return false;
  for (const o of item.options) {
    if (!o || typeof o.text !== "string" || typeof o.w !== "object" || !o.w) return false;
    const keys = Object.keys(o.w);
    if (!keys.length) return false;
    for (const k of keys) {
      if (!DIMS.includes(k) || !Number.isFinite(Number(o.w[k]))) return false;
    }
  }
  return true;
}

// 从题库池抽题：每个场景维度随机抽 1 题，第 8 题用固定天气直选（计分锚点）
function pickFromBank(bank: Record<string, any[]>): any[] {
  const qs: any[] = [];
  for (let i = 0; i < SCENE_BADGES.length; i++) {
    const badge = SCENE_BADGES[i];
    const pool = Array.isArray(bank?.[badge]) ? bank[badge].filter(validSingle) : [];
    let picked: any = null;
    if (pool.length) {
      picked = { ...pool[Math.floor(Math.random() * pool.length)], badge };
    } else {
      picked = { ...FALLBACK_QUESTIONS[i] };
    }
    qs.push(picked);
  }
  qs.push({ ...FALLBACK_QUESTIONS[7] }); // 收尾天气直选
  return qs;
}

async function callDeepSeek(label: string, temperature: number): Promise<any[]> {
  const sys = [
    "你是「情绪气象台」的专业出题引擎，为指定身份生成情境化心情测试题（娱乐互动、仅供自我探索，不做任何诊断）。",
    "【专业出题规范】",
    "1. 共 8 题，前 7 题覆盖该身份真实一天的场景：清晨醒来、上工/通勤、白天忙碌、傍晚收工、深夜睡前、情绪低落时、与人相处；每题恰好 4 个选项。",
    "2. 情境锚定：每题锚定该身份一个具体、真实、有画面感的生活瞬间，贴合「" + label + "」的真实细节，让该身份的人一看就「被说中」。",
    "3. 行为化表述：写「你会怎么做/怎么想/什么感受」，不贴抽象标签；4 个选项长度相近、语气平等，不暗示哪个更对。",
    "4. 深度分层：从表面行为深入到情绪动机/应对策略，避免「你开心吗」这类浮面题。",
    "5. 第 8 题是收尾天气直选，固定 7 个选项文字：晴朗、通透、平静、湿润、热烈、绚烂、清澈。",
    "6. 每个选项必须给字段 w：映射到 7 种天气维度的整数权重，主维度给 2、可给一个次维度 1。维度含义：",
    "sun=阳光有感染力行动派；sky=清醒稳定治愈；mist=温柔内敛高共情；rain=敏感细腻洞察力；storm=行动力强敢表达；rainbow=创造力乐观氛围制造；snow=冷静独立思考。",
    "7. 绝对禁止：不涉及疾病/症状/诊断/药物/治疗/自伤等任何医学或心理健康诊疗内容。",
    "【高质量示例（模仿这种写法）】好的题：题目「上午十点你盯着同一段代码二十分钟没找到问题，你会？」，选项「站起来走走接杯水，换个环境再看」（sky）/「在代码里加打印，用最直接的方法定位」（storm）。特征是具体到时间/动作、选项简短口语化、有画面感、被说中感强。差的题：「你工作时心情如何」——太浮面，禁止。",
    "8. 只输出 JSON，形如 {\"questions\":[{\"badge\":\"清晨\",\"title\":\"…\",\"options\":[{\"text\":\"…\",\"w\":{\"sun\":2}}]}]}，不要任何解释。",
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

// ===== S4 AI 输出合规二次审查：生成题目含敏感词/医疗暗示则弃用（回退兜底题） =====
const AI_OUT_ILLEGAL = /诊断|症状|疾病|药物|治疗|患病|抑郁|焦虑障碍|自伤|自残|自杀|医疗|就诊|服药|确诊|疗效|心理疾病|精神疾病|病症|肿瘤|癌|过敏|发烧|感冒药|医院|科室|处方|医嘱|心理咨询师|医生诊断/i;
function contentSafe(q: any[]): boolean {
  if (!Array.isArray(q)) return false;
  let flat = "";
  for (const it of q) {
    if (!it) return false;
    flat += (it.title || "") + " ";
    if (Array.isArray(it.options)) for (const o of it.options) flat += (o?.text || "") + " ";
  }
  if (ILLEGAL_PAT.test(flat)) return false;
  if (AI_OUT_ILLEGAL.test(flat)) return false;
  return true;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return respond(origin, 405, { ok: false, code: "method" });

  let label = "", licKey = "", deviceId = "";
  try {
    const body = await req.json();
    label = String(body.identity || "").trim().slice(0, 20);
    // 许可证密钥：清洗方式与 verify-key 保持一致（trim + 大写 + 去空白，保留连字符）
    licKey = String(body.key || "").trim().toUpperCase().replace(/\s+/g, "");
    deviceId = String(body.device_id || "").trim().slice(0, 64);
  } catch {
    return respond(origin, 400, { ok: false, code: "bad_body" });
  }
  if (!label) return respond(origin, 400, { ok: false, code: "no_identity" });
  // 合法性校验：拦截敏感/非职业/纯符号输入，避免无效 AI 调用与脏数据
  if (!isLegalIdentity(label)) return respond(origin, 400, { ok: false, code: "invalid_identity", message: "请输入中文职业或身份，内容需合规" });

  const key = normKey(label);

  // 1) 连接数据库（service_role）
  const { createClient } = await import("jsr:@supabase/supabase-js@2");
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } },
  );

  // ===== P0-1 + S2 密钥鉴权：无 key / 坏 key / disabled / 过期 → 拒绝取题，不触发 AI =====
  // used / unused 均放行（与 verify-key 一致，允许已购用户刷新 / 重测）
  if (!licKey) {
    return respond(origin, 400, { ok: false, code: "invalid_key", message: "请先输入测评密钥" });
  }
  const { data: licRow, error: licErr } = await supabase
    .from("license_keys")
    .select("key,status,expires_at")
    .eq("key", licKey)
    .maybeSingle();
  if (licErr) return respond(origin, 500, { ok: false, code: "server" });
  if (!licRow || licRow.status === "disabled") {
    return respond(origin, 200, { ok: false, code: "invalid_key", message: "密钥已失效/未登录，请重新输入密钥" });
  }
  if (licRow.expires_at && new Date(licRow.expires_at).getTime() < Date.now()) {
    return respond(origin, 200, { ok: false, code: "invalid_key", message: "密钥已过期，请重新购买" });
  }
  // ===== S2 设备上限：携带 device_id 时登记并校验；未携带则放行（脚本可绕过设备上限，主付费墙仍有效） =====
  if (deviceId) {
    const { data: dev } = await supabase.rpc("license_register_device", { p_key: licKey, p_device: deviceId });
    if (dev?.reason === "device_limit") {
      return respond(origin, 200, { ok: false, code: "invalid_key", message: "该密钥已绑定过多设备，请使用已绑定设备" });
    }
  }

  // 2) 题库池命中（热门身份：随机抽 8 题，每次不同）
  const { data: bankHit } = await supabase
    .from("question_bank")
    .select("identity_label,bank")
    .eq("identity_key", key)
    .maybeSingle();
  if (bankHit?.bank) {
    const qs = pickFromBank(bankHit.bank);
    await supabase.rpc("inc_hits", { p_key: key }).then(undefined, () => {});
    return respond(origin, 200, { ok: true, cached: true, from_bank: true, identity_label: bankHit.identity_label, questions: qs });
  }

  // 2.5) 模糊匹配：用户输入与已存在身份「沾边」则复用，避免浪费 AI 算力
  const { data: allIdentities } = await supabase
    .from("question_bank")
    .select("identity_label,identity_key,bank");
  if (Array.isArray(allIdentities) && allIdentities.length) {
    // 2.5.1) 语义别名解析：口语化称呼直接映射到正式身份（如「码农」→「程序员」）
    const canon = aliasResolve(label);
    if (canon) {
      const canonical = allIdentities.find((r) => r.identity_label === canon);
      if (canonical?.bank) {
        const qs = pickFromBank(canonical.bank);
        await supabase.rpc("inc_hits", { p_key: canonical.identity_key }).then(undefined, () => {});
        return respond(origin, 200, {
          ok: true, cached: true, from_bank: true, fuzzy: true, alias: canon,
          identity_label: canonical.identity_label,
          matched_input: label,
          questions: qs,
        });
      }
    }
    // 2.5.2) 字面相似：子串包含 / 编辑距离近似
    const matched = allIdentities.find((r) => fuzzyMatch(label, r.identity_label));
    if (matched?.bank) {
      const qs = pickFromBank(matched.bank);
      await supabase.rpc("inc_hits", { p_key: matched.identity_key }).then(undefined, () => {});
      return respond(origin, 200, {
        ok: true, cached: true, from_bank: true, fuzzy: true,
        identity_label: matched.identity_label,
        matched_input: label,
        questions: qs,
      });
    }
  }

  // 3) 单套缓存命中（冷门身份已生成）
  const { data: hit } = await supabase
    .from("question_cache")
    .select("identity_label,questions")
    .eq("identity_key", key)
    .maybeSingle();
  if (hit?.questions) {
    await supabase.rpc("inc_hits", { p_key: key }).then(undefined, () => {});
    return respond(origin, 200, { ok: true, cached: true, from_bank: false, identity_label: hit.identity_label, questions: hit.questions });
  }

  // 4) 均未命中 → 调 DeepSeek 生成单套并缓存（冷门身份兜底）
  // ===== P0-2 AI 限流：按密钥窗口 + 全局窗口双兜底，防止脚本循环刷爆账单 =====
  let questions: any[] | null = null;
  let limited = false;
  // 单密钥：每 5 分钟最多触发 AI 2 次；全局：每分钟最多 20 次（防多 key 拉犁的安全兜底）
  const { data: okKey } = await supabase.rpc("ai_acquire", { p_bucket: "k:" + licKey, p_window_seconds: 300, p_max: 2 });
  const { data: okGlobal } = await supabase.rpc("ai_acquire", { p_bucket: "g", p_window_seconds: 60, p_max: 20 });
  limited = okKey !== true || okGlobal !== true;
  if (!limited) {
    try {
      let raw = await callDeepSeek(label, 0.9);
      if (!(validate(raw) && contentSafe(raw))) {
        raw = await callDeepSeek(label, 0.5);
      }
      if (validate(raw) && contentSafe(raw)) questions = normalize(raw);
    } catch { /* 继续兜底 */ }
  }

  const source = questions ? "ai" : "fallback";
  const finalQ = questions || FALLBACK_QUESTIONS;
  await supabase.from("question_cache").upsert({
    identity_key: key, identity_label: label, questions: finalQ, source,
  }, { onConflict: "identity_key" });

  return respond(origin, 200, { ok: true, cached: false, from_bank: false, identity_label: label, questions: finalQ });
});
