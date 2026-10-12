-- ===== 热门身份题库池：按场景维度分桶的多题池（测评随机抽题）=====

create table if not exists public.question_bank (
  id             uuid primary key default gen_random_uuid(),
  identity_key   text not null unique,   -- 标准化身份
  identity_label text not null,         -- 原始显示名
  bank           jsonb not null,        -- { "清晨":[题xN], "上工":[题xN], ... 7个场景维度 }
  source         text not null default 'ai',  -- ai：AI 预生成
  created_at     timestamptz not null default now()
);

-- RLS：启用且不建 policy，仅 service_role（Edge Function / 运维脚本）可访问
alter table public.question_bank enable row level security;
revoke all on public.question_bank from anon, authenticated;
