-- ===== 身份题目缓存表（混合方案：AI 生成 + 缓存复用，最大化降低成本）=====

create table if not exists public.question_cache (
  id             uuid primary key default gen_random_uuid(),
  identity_key   text not null unique,   -- 标准化身份（去空白/标点，小写），用于匹配
  identity_label text not null,         -- 原始显示名，如「程序员」
  questions      jsonb not null,        -- 题目数组（结构与前端 QUESTIONS 一致）
  source         text not null default 'ai',  -- ai：AI 生成；fallback：兜底通用题
  hit_count      bigint not null default 0,    -- 缓存命中次数（统计成本/热度）
  created_at     timestamptz not null default now()
);

-- 按命中热度排序用
create index if not exists question_cache_hits_idx on public.question_cache (hit_count desc);

-- RLS：启用且不建 policy，仅 service_role（Edge Function）可访问
alter table public.question_cache enable row level security;

-- 命中计数自增（仅 service_role / Edge Function 调用）
create or replace function public.inc_hits(p_key text)
returns void language sql security definer as $$
  update public.question_cache set hit_count = hit_count + 1 where identity_key = p_key;
$$;

-- 双保险：收回匿名/登录用户的所有直接权限
revoke all on public.question_cache from anon, authenticated;
revoke execute on function public.inc_hits(text) from anon, authenticated;
