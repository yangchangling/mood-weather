-- ===== 安全加固（二）：允许 key 列置空（明文迁移后清空）=====
-- license_keys.key / license_devices.key 原为 text not null；回填 key_hash 后需置空明文，故放开 NOT NULL。
alter table public.license_keys    alter column key drop not null;
alter table public.license_devices alter column key drop not null;
