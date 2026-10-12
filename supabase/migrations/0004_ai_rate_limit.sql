-- ===== AI 调用限流表（P0-2）：防止脚本循环刷爆 DeepSeek 账单 =====
-- 窗口桶：bucket 为主键，可按密钥（'k:<licKey>'）或全局（'g'）分别计数。
-- 每次窗口过期后重置，窗口内超限则拒绝。

create table if not exists public.ai_rate_limit (
  bucket       text primary key,          -- 限流桶：'k:<许可证key>' 按密钥 / 'g' 全局
  window_start timestamptz not null default now(),
  count        int not null default 0
);

-- RLS：启用且不建 policy，仅 service_role（Edge Function）可访问
alter table public.ai_rate_limit enable row level security;
revoke all on public.ai_rate_limit from anon, authenticated;

-- 原子申请一次 AI 配额：
--   桶不存在 → 建桶并计数 1，返回 true
--   窗口已过期 → 重置窗口并计数 1，返回 true
--   窗口内未超限 → 计数 +1，返回 true
--   窗口内已超限 → 返回 false（应拒绝本次 AI 调用）
-- 已存在桶用行锁（for update）串行化并发，避免并发穿透。
create or replace function public.ai_acquire(p_bucket text, p_window_seconds int, p_max int)
returns boolean language plpgsql security definer as $$
declare
  r public.ai_rate_limit;
begin
  select * into r from public.ai_rate_limit where bucket = p_bucket for update;
  if r is null then
    insert into public.ai_rate_limit(bucket, window_start, count)
    values (p_bucket, now(), 1)
    on conflict (bucket) do nothing;
    return true;
  end if;
  if now() - r.window_start >= make_interval(secs => p_window_seconds) then
    update public.ai_rate_limit set window_start = now(), count = 1 where bucket = p_bucket;
    return true;
  end if;
  if r.count >= p_max then
    return false;
  end if;
  update public.ai_rate_limit set count = count + 1 where bucket = p_bucket;
  return true;
end $$;

revoke execute on function public.ai_acquire(text, int, int) from anon, authenticated;
