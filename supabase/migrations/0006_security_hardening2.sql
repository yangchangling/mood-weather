-- ===== 安全加固（二）：密钥哈希化 + 会话票据基础（①②）=====
-- 目标：库中不存明文 key；设备表改存 key_hash；后台可脱敏展示。
-- 存量明文 key 由运维脚本（env HASH_SECRET + SUPABASE_SERVICE_ROLE）回填为 key_hash 并置空 key。

-- 1. license_keys 增加 key_hash（HMAC 结果，唯一）与 key_display（脱敏展示，供后台识别）
alter table public.license_keys
  add column if not exists key_hash   text,
  add column if not exists key_display text;

create unique index if not exists license_keys_key_hash_idx on public.license_keys(key_hash);

-- 2. license_devices 增加 key_hash 列；新增唯一约束 (key_hash, device_id)
alter table public.license_devices
  add column if not exists key_hash text;
alter table public.license_devices
  drop constraint if exists license_devices_kh_did_uniq;
alter table public.license_devices
  add constraint license_devices_kh_did_uniq unique (key_hash, device_id);

-- 3. 重写 license_register_device：按 key_hash 匹配密钥，设备表写 key_hash
drop function if exists public.license_register_device(text, text);
create or replace function public.license_register_device(p_key_hash text, p_device text)
returns jsonb language plpgsql security definer as $$
declare
  lim int; cnt int; kh text := coalesce(p_key_hash, '');
begin
  select device_limit into lim from public.license_keys where key_hash = kh;
  if lim is null then return jsonb_build_object('ok', false, 'reason', 'no_key'); end if;
  insert into public.license_devices(key_hash, device_id)
  values (kh, p_device)
  on conflict (key_hash, device_id)
  do update set last_seen = now();
  select count(*) into cnt from public.license_devices where key_hash = kh;
  if cnt > lim then
    return jsonb_build_object('ok', false, 'reason', 'device_limit', 'count', cnt, 'limit', lim);
  end if;
  return jsonb_build_object('ok', true, 'count', cnt, 'limit', lim);
end $$;
revoke execute on function public.license_register_device(text, text) from anon, authenticated;
