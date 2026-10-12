#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密钥哈希化回填：把 license_keys / license_devices 里的明文 key 转为 HMAC key_hash 并置空明文。
用法：export SUPABASE_SERVICE_ROLE=<service_role> HASH_SECRET=<secret>
"""
import os, json, hmac, hashlib, urllib.request, urllib.parse

SB_URL = "https://nyynghsbcfkbmgesnfzx.supabase.co/rest/v1"
SR = os.environ.get("SUPABASE_SERVICE_ROLE", "").strip()
SECRET = os.environ.get("HASH_SECRET", "").strip()
assert SR and SECRET, "需要环境变量 SUPABASE_SERVICE_ROLE 与 HASH_SECRET"

def hkey(raw):
    return hmac.new(SECRET.encode(), ("lic:" + raw).encode(), hashlib.sha256).hexdigest()

def mask(k):
    if len(k) <= 8:
        return k[:2] + "-••••"
    return k[:4] + "-••••-" + k[-4:]

def req(method, path, body=None):
    r = urllib.request.Request(SB_URL + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"apikey": SR, "Authorization": "Bearer " + SR,
                 "Content-Type": "application/json", "Prefer": "return=minimal"})
    with urllib.request.urlopen(r) as resp:
        return resp.read().decode()

# 读明文密钥（尚未被置空的）
keys = json.loads(req("GET", "/license_keys?select=id,key&key=not.is.null"))
devs = json.loads(req("GET", "/license_devices?select=id,key&key=not.is.null"))
print("license_keys 待回填:", len(keys), "| license_devices 待回填:", len(devs))

n = 0
for r in keys:
    kh = hkey(r["key"])
    # 先处理设备表（需要明文 key 映射），再置空 license_keys
    req("PATCH", "/license_keys?id=eq." + r["id"], {"key_hash": kh, "key_display": mask(r["key"]), "key": None})
    n += 1
print("license_keys 回填完成:", n)

m = 0
for r in devs:
    kh = hkey(r["key"])
    req("PATCH", "/license_devices?id=eq." + r["id"], {"key_hash": kh, "key": None})
    m += 1
print("license_devices 回填完成:", m)

# 核对：不再存在明文 key
left = json.loads(req("GET", "/license_keys?select=id&key=not.is.null"))
ld = json.loads(req("GET", "/license_devices?select=id&key=not.is.null"))
print("残留明文 license_keys:", len(left), "| license_devices:", len(ld))
