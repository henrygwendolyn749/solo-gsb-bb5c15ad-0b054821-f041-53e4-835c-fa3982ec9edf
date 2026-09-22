#!/usr/bin/env python3
"""/secure-request 签名与调用示例（仅依赖 Python 3 标准库）。

用法：
    python examples/secure_request_example.py plan
    python examples/secure_request_example.py assemble
    SECURE_REQUEST_KEYS=my-key=my-secret python examples/secure_request_example.py plan

环境变量：
    RANGE_PLANNER_URL  服务地址（默认 http://127.0.0.1:8080）
    SECURE_REQUEST_KEYS 与服务端相同格式的 key_id=secret（默认 demo-key=...）
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE_URL = os.environ.get("RANGE_PLANNER_URL", "http://127.0.0.1:8080")
KEY_ID = "demo-key"
SECRET = os.environ.get(
    "SECURE_REQUEST_KEYS",
    "demo-key=0123456789abcdef0123456789abcdef",
).partition("=")[2].encode("utf-8")


def canonical_json(obj: object) -> bytes:
    """必须与服务端完全一致的固定规范化：键排序、无空白、UTF-8。"""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign(operation: str, payload: dict) -> dict:
    envelope = {
        "operation": operation,
        "payload": payload,
        "key_id": KEY_ID,
        "timestamp": int(time.time()),
        "nonce": uuid.uuid4().hex,
    }
    # 签名串包含 operation/payload/key_id/timestamp/nonce（不含 signature）。
    envelope["signature"] = hmac.new(
        SECRET, canonical_json(envelope), hashlib.sha256
    ).hexdigest()
    return envelope


def call(operation: str, payload: dict) -> dict:
    body = json.dumps(sign(operation, payload)).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/secure-request",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode()}")
        sys.exit(1)


PLAN_PAYLOAD = {
    "object_length": 256,
    "ranges": [
        {"type": "interval", "start": 0, "end": 99},
        {"type": "suffix", "last_n": 16},
    ],
    "max_gap": 8,
    "fetch_limit": 128,
    "cached_blocks": [{"cache_id": "cdn-a", "start": 40, "end": 59}],
}

# 三个回源块的内容按 blocks[].range_header 回源获得，
# 缓存块内容直接从本地缓存读取（见 main() 中的模拟）。


def main() -> None:
    operation = sys.argv[1] if len(sys.argv) > 1 else "plan"

    if operation == "plan":
        print(json.dumps(call("plan", PLAN_PAYLOAD), ensure_ascii=False, indent=2))
        return

    if operation == "assemble":
        plan = call("plan", PLAN_PAYLOAD)
        # 模拟用 range_header 回源：这里直接按偏移从一个 256 字节的
        # 虚拟对象中切片；缓存命中部分直接从本地缓存读取。
        obj = bytes((i % 256 for i in range(256)))  # 演示用虚拟对象
        # 用与对象一致的字节覆盖示例常量，保持脚本自洽可运行：
        fetch_data = {}
        for block in plan["blocks"]:
            fetch_data[block["index"]] = obj[block["start"] : block["end"] + 1]
        cache_data = {
            cb["cache_id"]: obj[cb["start"] : cb["end"] + 1]
            for cb in plan["cached_blocks"]
        }

        import base64

        assemble_payload = {
            "object_length": plan["object_length"],
            "blocks": plan["blocks"],
            "mappings": plan["mappings"],
            "cached_blocks": plan["cached_blocks"],
            "contents": [
                {"block_index": idx, "data_b64": base64.b64encode(data).decode()}
                for idx, data in sorted(fetch_data.items())
            ],
            "cache_contents": [
                {"cache_id": cid, "data_b64": base64.b64encode(data).decode()}
                for cid, data in cache_data.items()
            ],
        }
        result = call("assemble", assemble_payload)
        print(json.dumps(result, ensure_ascii=False, indent=2))

        # 重组结果与原对象对应范围逐字节核对。
        for item in result["ranges"]:
            actual = base64.b64decode(item["data_b64"])
            expect = obj[item["start"] : item["end"] + 1]
            assert actual == expect, f"范围 {item['index']} 重组不一致"
        print("OK: assemble 重组结果与原范围一致")
        return

    print(f"未知操作：{operation}（支持 plan / assemble）")
    sys.exit(2)


if __name__ == "__main__":
    main()
