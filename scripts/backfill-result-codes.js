// 历史结果回补 result_code 脚本
// 用法:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE=... node scripts/backfill-result-codes.js --dry-run   # 仅统计需回补条数
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE=... node scripts/backfill-result-codes.js            # 实际回补
// 说明：对 mood_results 中 result_code 为空的记录生成唯一结果码并回填，字符集与 submit-result 后端一致，
//       只写 result_code 字段，不触碰其他数据；REST 唯一冲突(409)时换码重试。
const API = process.env.SUPABASE_URL || "https://nyynghsbcfkbmgesnfzx.supabase.co";
const SR = process.env.SUPABASE_SERVICE_ROLE || process.env.SERVICE_ROLE_KEY;
const DRY = process.argv.includes("--dry-run");
if (!SR) { console.error("缺少环境变量 SUPABASE_SERVICE_ROLE"); process.exit(1); }

const ALPHA = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // 与 submit-result 的 RC_ALPHABET 一致
function genCode() {
  let s = "";
  for (let i = 0; i < 6; i++) s += ALPHA[Math.floor(Math.random() * ALPHA.length)];
  return "R-" + s;
}
const H = { apikey: SR, Authorization: "Bearer " + SR, "Content-Type": "application/json" };
async function listNull(offset) {
  const r = await fetch(`${API}/rest/v1/mood_results?select=id&result_code=is.null&limit=1000&offset=${offset}`, { headers: H });
  return await r.json();
}

(async () => {
  let total = 0, done = 0, fail = 0;
  while (true) {
    const rows = await listNull(total);
    if (!rows || !Array.isArray(rows) || !rows.length) break;
    for (const row of rows) {
      total++;
      if (DRY) continue;
      for (let t = 0; t < 5; t++) {
        const code = genCode();
        const res = await fetch(`${API}/rest/v1/mood_results?id=eq.${row.id}`, {
          method: "PATCH", headers: H, body: JSON.stringify({ result_code: code }),
        });
        if (res.status === 204) { done++; break; }
        if (res.status === 409) continue; // 唯一冲突 → 换码重试
        fail++; break;
      }
    }
    if (!Array.isArray(rows) || rows.length < 1000) break;
  }
  console.log(DRY ? `[dry-run] 待回补 ${total} 条` : `回补完成：共${total} 成功${done} 失败${fail}`);
})();
