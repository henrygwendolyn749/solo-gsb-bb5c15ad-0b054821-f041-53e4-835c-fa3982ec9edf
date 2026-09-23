"""/multipart-parse 端点的解析与校验测试，同时回归 /plan、/assemble。"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

BOUNDARY = "Wk9 Boundary_42:/"
OBJ_LEN = 100


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def build_body(
    parts: list[tuple[dict[str, str], bytes]],
    boundary: str = BOUNDARY,
    *,
    leading_crlf: bool = True,
    close: bytes | None = None,
) -> bytes:
    """按 RFC 2046 拼装 multipart 体；close 可覆盖关闭分隔符以构造畸形输入。"""
    out = b"\r\n" if leading_crlf else b""
    for headers, payload in parts:
        out += b"--" + boundary.encode() + b"\r\n"
        for k, v in headers.items():
            out += f"{k}: {v}\r\n".encode()
        out += b"\r\n" + payload + b"\r\n"
    out += close if close is not None else b"--" + boundary.encode() + b"--\r\n"
    return out


def std_headers(start: int, end: int, total: int = OBJ_LEN, ct: str = "text/plain"):
    return {
        "Content-Range": f"bytes {start}-{end}/{total}",
        "Content-Type": ct,
    }


def call(raw_body: bytes, ranges, boundary=BOUNDARY, object_length=OBJ_LEN, **extra):
    return client.post(
        "/multipart-parse",
        json={
            "object_length": object_length,
            "ranges": ranges,
            "boundary": boundary,
            "response_b64": b64(raw_body),
            **extra,
        },
    )


INTERVAL_0_9 = {"type": "interval", "start": 0, "end": 9}
INTERVAL_20_29 = {"type": "interval", "start": 20, "end": 29}
SUFFIX_5 = {"type": "suffix", "last_n": 5}


# ------------------------------- 成功路径 -------------------------------


def test_happy_path_intervals_and_suffix_out_of_order():
    d09 = bytes(range(10))
    d2029 = bytes((i % 256 for i in range(20, 30)))
    d9599 = b"\xff\xfe\xfd\xfc\xfb"
    body = build_body(
        [
            # 故意乱序，且头部大小写混用、带参数与多余可忽略头部
            (
                {
                    "content-range": "bytes 95-99/100",
                    "Content-TYPE": 'text/plain; charset="us-ascii"',
                    "X-Upstream": "edge-7",
                },
                d9599,
            ),
            (std_headers(0, 9), d09),
            (std_headers(20, 29), d2029),
        ]
    )
    resp = call(body, [INTERVAL_0_9, INTERVAL_20_29, SUFFIX_5])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["object_length"] == 100
    assert data["content_type"] == "text/plain"
    assert [r["index"] for r in data["ranges"]] == [0, 1, 2]
    assert [r["type"] for r in data["ranges"]] == ["interval", "interval", "suffix"]
    assert [(r["start"], r["end"], r["length"]) for r in data["ranges"]] == [
        (0, 9, 10),
        (20, 29, 10),
        (95, 99, 5),
    ]
    assert [base64.b64decode(r["data_b64"]) for r in data["ranges"]] == [
        d09,
        d2029,
        d9599,
    ]


def test_suffix_longer_than_object_normalizes_to_whole_object():
    payload = b"abc"
    body = build_body([(std_headers(0, 2, total=3), payload)])
    resp = call(
        body,
        [{"type": "suffix", "last_n": 50}],
        object_length=3,
    )
    assert resp.status_code == 200, resp.text
    r = resp.json()["ranges"][0]
    assert (r["start"], r["end"], r["length"]) == (0, 2, 3)
    assert base64.b64decode(r["data_b64"]) == payload


def test_no_leading_crlf_is_accepted():
    body = build_body([(std_headers(0, 9), bytes(range(10)))], leading_crlf=False)
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 200, resp.text


def test_binary_payload_with_crlf_and_boundary_like_bytes():
    # 正文中包含 CRLF、差一字符的伪边界以及前面不带 CRLF 的完整 boundary；
    # 只有 CRLF+完整 boundary 才是真正的分隔符。
    payload = (
        b"\r\n--" + BOUNDARY[:-1].encode() + b"\r\n"
        + BOUNDARY.encode() + b"X\r\n\x00\x01\r\n"
    )
    body = build_body([(std_headers(0, len(payload) - 1, total=100), payload)])
    resp = call(body, [{"type": "interval", "start": 0, "end": len(payload) - 1}])
    assert resp.status_code == 200, resp.text
    assert base64.b64decode(resp.json()["ranges"][0]["data_b64"]) == payload


def test_single_byte_part():
    body = build_body([(std_headers(50, 50), b"Z")])
    resp = call(body, [{"type": "interval", "start": 50, "end": 50}])
    assert resp.status_code == 200, resp.text
    assert resp.json()["ranges"][0]["data_b64"] == b64(b"Z")


# ------------------------------- 结构 / boundary -------------------------------


def test_wrong_boundary():
    body = build_body([(std_headers(0, 9), bytes(range(10)))], boundary="other")
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "bad_boundary"
    assert err["detail"][0]["loc"] == "response_b64"


def test_boundary_prefix_lookalike_rejected():
    # 关闭分隔符写成 --boundary-x（边界前缀但不是合法分隔行）。
    body = build_body(
        [(std_headers(0, 9), bytes(range(10)))],
        close=b"--" + BOUNDARY.encode() + b"-x\r\n",
    )
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "bad_boundary"


def test_epilogue_rejected():
    body = build_body([(std_headers(0, 9), bytes(range(10)))]) + b"junk"
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "bad_boundary"


def test_missing_crlf_after_closing_boundary():
    body = build_body(
        [(std_headers(0, 9), bytes(range(10)))],
        close=b"--" + BOUNDARY.encode() + b"--",
    )
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "malformed_multipart"


def test_truncated_body():
    body = build_body([(std_headers(0, 9), bytes(range(10)))])[:-10]
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] in {"bad_boundary", "malformed_multipart"}


def test_invalid_boundary_chars():
    resp = client.post(
        "/multipart-parse",
        json={
            "object_length": OBJ_LEN,
            "ranges": [INTERVAL_0_9],
            "boundary": "bad boundary",
            "response_b64": b64(b""),
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"] in {"invalid_boundary", "invalid_request"}


def test_empty_multipart_body():
    body = b"--" + BOUNDARY.encode() + b"--\r\n"
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "empty_multipart"


def test_preamble_rejected():
    body = b"preamble junk\r\n" + build_body(
        [(std_headers(0, 9), bytes(range(10)))]
    )
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "bad_boundary"


# ------------------------------- 头部注入 / 头部非法 -------------------------------


def test_bare_lf_header_rejected():
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b"Content-Range: bytes 0-9/100\n"
        b"Content-Type: text/plain\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "header_injection"


def test_folded_header_rejected():
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b"Content-Range: bytes 0-9/100\r\n"
        b"Content-Type: text/plain\r\n"
        b" X-Injected: yes\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "header_injection"
    assert resp.json()["detail"][0]["part_index"] == 0


def test_non_ascii_header_rejected():
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b"Content-Range: bytes 0-9/100\r\n"
        b"X-Test: caf\xc3\xa9\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    # 带非法头部但缺少 Content-Type：注入检测应先于缺头部检测
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "header_injection"


def test_header_without_colon_rejected():
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b"Content-Range bytes 0-9/100\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "invalid_part_header"


# ------------------------------- Content-Range / Content-Type -------------------------------


@pytest.mark.parametrize(
    "cr_value,code",
    [
        ("bytes 0-9/101", "content_range_total_mismatch"),
        ("bytes 0-9/99", "content_range_total_mismatch"),
        ("bytes 0-100/100", "content_range_out_of_bounds"),
        ("bytes 9-5/100", "content_range_inverted"),
        ("items 0-9/100", "invalid_content_range_unit"),
        ("bytes */100", "invalid_content_range"),
        ("bytes 0-9/*", "invalid_content_range"),
        ("bytes 0-9", "invalid_content_range"),
    ],
)
def test_bad_content_range(cr_value, code):
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        + f"Content-Range: {cr_value}\r\n".encode()
        + b"Content-Type: text/plain\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == code
    assert err["detail"][0]["loc"].endswith(".headers.Content-Range")


def test_missing_content_range():
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\nContent-Type: text/plain\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "missing_content_range"


def test_part_length_mismatch():
    body = build_body([(std_headers(0, 9), b"short")])
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "part_length_mismatch"
    assert err["detail"][0]["part_index"] == 0


def test_missing_content_type():
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\nContent-Range: bytes 0-9/100\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "missing_content_type"


def test_invalid_content_type():
    body = build_body(
        [(
            {
                "Content-Range": "bytes 0-9/100",
                "Content-Type": "text/plain; bogus",
            },
            bytes(range(10)),
        )]
    )
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "invalid_content_type"


def test_content_type_mismatch_between_parts():
    body = build_body(
        [
            (std_headers(0, 9, ct="text/plain"), bytes(range(10))),
            (std_headers(20, 29, ct="application/octet-stream"), bytes(10)),
        ]
    )
    resp = call(body, [INTERVAL_0_9, INTERVAL_20_29])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "content_type_mismatch"
    assert err["detail"][0]["part_index"] == 1


def test_duplicate_required_header():
    raw = (
        b"--" + BOUNDARY.encode() + b"\r\n"
        b"Content-Range: bytes 0-9/100\r\n"
        b"Content-Range: bytes 0-9/100\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        + bytes(range(10))
        + b"\r\n--" + BOUNDARY.encode() + b"--\r\n"
    )
    resp = call(raw, [INTERVAL_0_9])
    assert resp.status_code == 422
    assert resp.json()["error"] == "duplicate_header"


# ------------------------------- part / range 对应关系 -------------------------------


def test_missing_part():
    body = build_body([(std_headers(0, 9), bytes(range(10)))])
    resp = call(body, [INTERVAL_0_9, INTERVAL_20_29])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "missing_part"
    assert err["detail"][0]["range_index"] == 1


def test_duplicate_part():
    body = build_body(
        [
            (std_headers(0, 9), bytes(range(10))),
            (std_headers(0, 9), bytes(range(10))),
        ]
    )
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "duplicate_part"
    assert err["detail"][0]["part_index"] == 1


def test_unexpected_part():
    body = build_body(
        [
            (std_headers(0, 9), bytes(range(10))),
            (std_headers(20, 29), bytes(10)),
        ]
    )
    resp = call(body, [INTERVAL_0_9])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "unexpected_part"
    assert err["detail"][0]["part_index"] == 1


def test_duplicate_expected_interval_rejected():
    resp = call(
        build_body([(std_headers(0, 9), bytes(range(10)))]),
        [INTERVAL_0_9, INTERVAL_0_9],
    )
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "duplicate_expected_range"
    assert err["detail"][0]["range_index"] == 1


def test_interval_and_suffix_normalizing_to_same_range_rejected():
    # 对象长度 10：interval [0,9] 与 suffix last_n>=10 规范化后相同
    body = build_body([(std_headers(0, 9, total=10), bytes(range(10)))])
    resp = call(
        body,
        [{"type": "interval", "start": 0, "end": 9}, {"type": "suffix", "last_n": 10}],
        object_length=10,
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "duplicate_expected_range"


def test_interval_out_of_bounds():
    resp = call(
        build_body([(std_headers(0, 9), bytes(range(10)))]),
        [{"type": "interval", "start": 0, "end": 100}],
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "range_out_of_bounds"


def test_interval_inverted():
    resp = call(
        build_body([(std_headers(5, 5), b"Z")]),
        [{"type": "interval", "start": 9, "end": 5}],
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "invalid_range"


def test_suffix_on_empty_object():
    body = build_body([]) if False else b"--" + BOUNDARY.encode() + b"--\r\n"
    resp = call(body, [{"type": "suffix", "last_n": 1}], object_length=0)
    assert resp.status_code == 422
    assert resp.json()["error"] == "unsatisfiable_suffix"


# ------------------------------- Base64 -------------------------------


def test_invalid_base64_chars():
    resp = client.post(
        "/multipart-parse",
        json={
            "object_length": OBJ_LEN,
            "ranges": [INTERVAL_0_9],
            "boundary": BOUNDARY,
            "response_b64": "!!!!not-base64",
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "invalid_base64"


def test_bad_base64_padding():
    resp = client.post(
        "/multipart-parse",
        json={
            "object_length": OBJ_LEN,
            "ranges": [INTERVAL_0_9],
            "boundary": BOUNDARY,
            "response_b64": "abc",  # 长度不是 4 的倍数
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"] == "invalid_base64"


def test_part_index_locator_points_to_offending_part():
    body = build_body(
        [
            (std_headers(0, 9), bytes(range(10))),
            (
                {
                    "Content-Range": "bytes 20-29/100",
                    "Content-Type": "application/octet-stream\rBcc: inject",
                },
                bytes(10),
            ),
        ]
    )
    resp = call(body, [INTERVAL_0_9, INTERVAL_20_29])
    assert resp.status_code == 422
    err = resp.json()
    assert err["error"] == "header_injection"
    assert err["detail"][0]["part_index"] == 1
    assert "parts[1]" in err["detail"][0]["loc"]


# ------------------------------- 既有端点兼容回归 -------------------------------


def test_plan_still_works():
    resp = client.post(
        "/plan",
        json={
            "object_length": 256,
            "ranges": [
                {"type": "interval", "start": 0, "end": 99},
                {"type": "suffix", "last_n": 16},
            ],
            "max_gap": 8,
            "fetch_limit": 128,
        },
    )
    assert resp.status_code == 200
    assert len(resp.json()["blocks"]) == 2


def test_assemble_still_works():
    obj = bytes(range(256))
    plan = client.post(
        "/plan",
        json={
            "object_length": 256,
            "ranges": [{"type": "interval", "start": 0, "end": 9}],
            "max_gap": 8,
            "fetch_limit": 128,
        },
    ).json()
    contents = [
        {"block_index": b["index"], "data_b64": b64(obj[b["start"] : b["end"] + 1])}
        for b in plan["blocks"]
    ]
    resp = client.post(
        "/assemble",
        json={
            "object_length": 256,
            "blocks": plan["blocks"],
            "mappings": plan["mappings"],
            "contents": contents,
        },
    )
    assert resp.status_code == 200
    out = resp.json()["ranges"][0]
    assert base64.b64decode(out["data_b64"]) == obj[:10]
