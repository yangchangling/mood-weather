-- 0009_key_sales.sql
-- 补货-发货对账（A+C 两步闭环）：
--   step1 补货：manage-key `gen` 自动生成明文密钥并返回给卖家一次（明文不落库，仅存 key_hash/key_display）。
--   step2 对账：manage-key `log-sale` 记录"哪把密钥发给了哪个订单"，供库存/对账。
-- 本表只存脱敏标识（key_display）与订单信息，不存密钥明文。
-- 写入方仅限 Edge Function（manage-key，使用 service_role），anon 不可读写。

create table if not exists key_sales (
  id uuid primary key default gen_random_uuid(),
  key_hash text not null,
  key_display text not null,
  order_no text,
  buyer text,
  sold_at timestamptz not null default now()
);

alter table key_sales enable row level security;

create index if not exists key_sales_key_hash_idx on key_sales (key_hash);
create index if not exists key_sales_sold_at_idx on key_sales (sold_at);
