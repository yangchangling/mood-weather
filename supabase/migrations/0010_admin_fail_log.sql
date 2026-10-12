-- 0010_admin_fail_log.sql
-- manage-key 管理后台登录失败限流日志
-- 用途：记录 manage-key 鉴权失败（错误密钥）的 IP 哈希与时间，用于暴力破解防护（IP 维度 + 全局维度锁定）
-- 安全：只存 IP 的 HMAC 哈希，不落明文 IP；仅函数(service_role)可写，anon 无任何策略

create table if not exists admin_fail_log (
  id        bigint generated always as identity primary key,
  ip_hash   text not null,
  created_at timestamptz not null default now()
);

create index if not exists admin_fail_log_ip_time_idx on admin_fail_log (ip_hash, created_at);
create index if not exists admin_fail_log_time_idx on admin_fail_log (created_at);

alter table admin_fail_log enable row level security;
-- 默认 RLS 拒绝一切；函数使用 service_role 绕过 RLS 写入/清理
