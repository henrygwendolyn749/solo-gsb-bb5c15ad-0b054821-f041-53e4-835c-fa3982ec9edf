#!/usr/bin/env python3
"""/multipart-parse 调用示例（仅依赖 Python 3 标准库）。

脚本模拟上游对一次多区间 Range 请求
（``Range: bytes=0-99, bytes=-16``）返回 ``multipart/byteranges`` 响应，
把完整响应体 Base64 后提交给 /multipart-parse，并核对返回内容与原对象一致。

用法：
    python examples/multipart_parse_example.py

环境变量：
    RANGE_PLANNER_URL  服务地址（默认 http://127.0.0.1:8080）
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("RANGE_PLANNER_URL", "http://127.0.0.1:8080")

OBJECT_LENGTH = 256
BOUNDARY = "8K3mZ9QrTx2v"  # 与上游 Content-Type: ...; boundary= 中的值一致


def fake_upstream_multipart(obj: bytes, spans: list[tuple[int, int]]) -> bytes:
    """构造上游 multipart/byteranges 完整响应体（严格 CRLF 分帧）。"""
    body = b""
    for start, end in spans:
        body += f"--{BOUNDARY}\r\n".encode("ascii")
        body += b"Content-Type: application/octet-stream\r\n"
        body += f"Content-Range: bytes {start}-{end}/{len(obj)}\r\n\r\n".encode(
            "ascii"
        )
        # part 正文后、下一个 boundary 前必须有 CRLF（分帧的一部分）
        body += obj[start : end + 1] + b"\r\n"
    body += f"--{BOUNDARY}--".encode("ascii")
    return body


def main() -> None:
    obj = bytes((i % 256 for i in range(OBJECT_LENGTH)))

    # 期望的两个范围：闭区间 [0,99] 与末尾 16 字节（suffix）。
    ranges = [
        {"type": "interval", "start": 0, "end": 99},
        {"type": "suffix", "last_n": 16},
    ]
    # 注意：上游可以按任意顺序回 part，解析结果始终按期望 ranges 顺序返回。
    wire = fake_upstream_multipart(obj, [(240, 255), (0, 99)])

    request = {
        "object_length": OBJECT_LENGTH,
        "ranges": ranges,
        "boundary": BOUNDARY,
        "expected_content_type": "application/octet-stream",
        "body_b64": base64.b64encode(wire).decode("ascii"),
    }

    http_req = urllib.request.Request(
        f"{BASE_URL}/multipart-parse",
        data=json.dumps(request).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(http_req, timeout=5) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.read().decode()}")
        sys.exit(1)

    print(json.dumps(result, ensure_ascii=False, indent=2))

    expected_spans = [(0, 99), (240, 255)]
    for item, (start, end) in zip(result["ranges"], expected_spans):
        actual = base64.b64decode(item["data_b64"])
        assert item["start"] == start and item["end"] == end, item
        assert actual == obj[start : end + 1], f"范围 {item['index']} 内容不一致"
    print("OK: multipart 解析结果与原对象对应范围逐字节一致")


if __name__ == "__main__":
    main()
