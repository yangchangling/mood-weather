-- ===== 安全加固（S2 密钥生命周期 / S6 缓存治理） =====

-- S2-1 密钥有效期 + 并发设备上限（null expires_at = 不过期；device_limit 默认 2）
alter table public.license_keys
  add column if not exists expires_at   timestamptz,
  add column if not exists device_limit int not null default 2;

-- S2-2 设备绑定表：记录每个密钥已登记的设备，唯一约束 (key, device_id)
create table if not exists public.license_devices (
  id         uuid primary key default gen_random_uuid(),
  key        text not null,
  device_id  text not null,
  first_seen timestamptz not null default now(),
  last_seen  timestamptz not null default now(),
  unique(key, device_id)
);
alter table public.license_devices enable row level security;
revoke all on public.license_devices from anon, authenticated;
create index if not exists license_devices_key_idx on public.license_devices(key);

-- S2-3 登记设备：新增则计 1，已存在则刷新 last_seen；返回是否超限。
--   超限时仍落库（可审计），但调用方应拒绝本次登录。
create or replace function public.license_register_device(p_key text, p_device text)
returns jsonb language plpgsql security definer as $$
declare
  lim int; cnt int;
begin
  select device_limit into lim from public.license_keys where key = p_key;
  if lim is null then return jsonb_build_object('ok', false, 'reason', 'no_key'); end if;
  insert into public.license_devices(key, device_id)
  values (p_key, p_device)
  on conflict (key, device_id)
  do update set last_seen = now();
  select count(*) into cnt from public.license_devices where key = p_key;
  if cnt > lim then
    return jsonb_build_object('ok', false, 'reason', 'device_limit', 'count', cnt, 'limit', lim);
  end if;
  return jsonb_build_object('ok', true, 'count', cnt, 'limit', lim);
end $$;
revoke execute on function public.license_register_device(text, text) from anon, authenticated;

-- S6-1 缓存治理：记录最后命中时间，供过期清理
alter table public.question_cache
  add column if not exists last_hit_at timestamptz;
create or replace function public.inc_hits(p_key text)
returns void language sql security definer as $$
  update public.question_cache set hit_count = hit_count + 1, last_hit_at = now() where identity_key = p_key;
$$;
revoke execute on function public.inc_hits(text) from anon, authenticated;

-- S6-2 缓存清理：删除陈旧缓存（fallback 且很久未命中 / 命中很低且久未命中）
create or replace function public.cleanup_question_cache(p_fallback_days int default 14, p_ai_days int default 60)
returns int language plpgsql security definer as $$
declare n int;
begin
  delete from public.question_cache
   where (source = 'fallback' and (last_hit_at is null and created_at < now() - make_interval(days => p_fallback_days)
                                   or last_hit_at < now() - make_interval(days => p_fallback_days)))
      or (source = 'ai' and hit_count <= 1 and coalesce(last_hit_at, created_at) < now() - make_interval(days => p_ai_days));
  get diagnostics n = row_count;
  return n;
end $$;
revoke execute on function public.cleanup_question_cache(int, int) from anon, authenticated;
