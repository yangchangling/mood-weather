-- 0008_consent_log.sql
-- PIPL 合规③：敏感个人信息（情绪/心理数据）需"单独同意"。consent_log 用于留痕，
-- 记录用户进入测评前对"同意将身份与出题请求发送给第三方 AI 用于出题"的单独同意。
-- 写入方仅限 Edge Function（record-consent，使用 service_role），anon 不可读写。

create table if not exists consent_log (
  id uuid primary key default gen_random_uuid(),
  key_hash text not null,
  device_id text not null,
  consent_version text not null,
  created_at timestamptz not null default now()
);

-- 仅启 RLS，默认 deny；service_role 走 bypass，anon 无任何 policy 即不可访问
alter table consent_log enable row level security;

create index if not exists consent_log_key_hash_idx on consent_log (key_hash);
create index if not exists consent_log_created_at_idx on consent_log (created_at);
