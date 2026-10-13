-- ===== 情绪气象台 · 结果二次进入（交付物扩展）=====
-- mood_results 增加：
--   result_code : 结果查询码（强随机短码，用户凭它二次进入查看结果；与销售密钥独立，只读、不消耗配额）
--   weather_json: 该次结果的关键快照（{topKey, identity, temp, type}），供二次进入重新渲染结果页
alter table public.mood_results add column if not exists result_code text;
alter table public.mood_results add column if not exists weather_json jsonb;

-- 结果码唯一（部分索引：仅对非空行约束，兼容历史无码数据）
create unique index if not exists mood_results_result_code_key on public.mood_results(result_code) where result_code is not null;
