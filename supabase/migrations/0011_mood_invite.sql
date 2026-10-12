-- ===== 情绪气象台 · 0011 结果落库 + 邀请返现 =====
-- 1) mood_results：测评结果匿名落库（用于"相似心情人群"匹配）
--    仅存匿名聚合所需字段，不含个人身份可识别明细
-- 2) invitations：分享邀请返现台账（分享者邀请好友，好友完成评测后分享者得 1 元站内券）
-- 3) coupon_balance：分享者累计返现额（站内抵扣，以"分"计，1 元 = 100 分）
-- 安全：三张表 RLS 默认拒绝（无策略），仅 service_role（Edge Functions）可读写

create table if not exists public.mood_results (
  id bigint generated always as identity primary key,
  key_hash text not null,
  device_id text not null,
  identity_label text not null,
  temp int not null,                 -- 情绪温度值（摄氏整数，如 26）
  result_label text not null,        -- 天气结果 key（sun/sky/mist/rain/storm/rainbow/snow）
  created_at timestamptz not null default now()
);
alter table public.mood_results enable row level security;

create table if not exists public.invitations (
  id bigint generated always as identity primary key,
  inviter_key_hash text not null,          -- 分享者密钥哈希（邀请人）
  invitee_key_hash text not null,          -- 被邀请者（好友）密钥哈希
  status text not null default 'pending',  -- pending / rewarded
  reward_cents int not null default 100,   -- 返现额（分），默认 100 分 = 1 元
  created_at timestamptz not null default now(),
  unique (inviter_key_hash, invitee_key_hash)
);
alter table public.invitations enable row level security;

create table if not exists public.coupon_balance (
  key_hash text primary key,
  balance_cents int not null default 0,    -- 累计可用返现（分），用于下次下单抵扣
  updated_at timestamptz not null default now()
);
alter table public.coupon_balance enable row level security;

-- 相似人群聚合查询（service_role 直查，供 submit-result 使用）
-- 参数：p_temp（本用户情绪温度）p_window（相似温差，默认 3）
create or replace function public.mood_similar(p_temp int, p_window int default 3)
returns json
language sql
security definer
set search_path = public
as $$
  with tgt as (
    select temp, result_label, identity_label
    from public.mood_results
    where abs(temp - p_temp) <= p_window
  )
  select json_build_object(
    'count', (select count(*) from tgt),
    'temp_min', (select min(temp) from tgt),
    'temp_max', (select max(temp) from tgt),
    'top_identity', (
      select identity_label from tgt
      group by identity_label
      order by count(*) desc, identity_label asc
      limit 1
    ),
    'top_result', (
      select result_label from tgt
      group by result_label
      order by count(*) desc, result_label asc
      limit 1
    )
  );
$$;
