-- ===== 情绪气象台 · 密钥池初始迁移 =====

-- 1. 密钥池表
create table if not exists public.license_keys (
  id          uuid primary key default gen_random_uuid(),
  key         text not null unique,                 -- 密钥，形如 MOOD-AB12-CD34
  status      text not null default 'unused' check (status in ('unused','used','disabled')),
  order_id    text,                                 -- 电商订单号（发货时回填，可空）
  created_at  timestamptz not null default now(),
  used_at     timestamptz                           -- 首次使用时间
);

-- 2. 索引（按状态筛选、发货统计）
create index if not exists license_keys_status_idx on public.license_keys (status);
create index if not exists license_keys_order_idx  on public.license_keys (order_id);

-- 3. 行级安全：启用 RLS，且不创建任何 policy
--    → anon / authenticated 完全无法直接读写，只有 service_role（Edge Function）可访问
alter table public.license_keys enable row level security;

-- 4. 预生成 20 个测试/首发密钥（MOOD-XXXX-XXXX）
insert into public.license_keys (key)
select 'MOOD-'
       || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 4))
       || '-'
       || upper(substr(replace(gen_random_uuid()::text, '-', ''), 5, 4))
from generate_series(1, 20)
on conflict do nothing;

-- 5. 关闭该表对匿名角色的所有遗留权限（双保险）
revoke all on public.license_keys from anon, authenticated;
