"""HTTP Range 回源规划与重组服务（缓存感知）。

POST /plan 接收对象总长度、若干闭区间或 suffix 范围、允许合并的最大间隙
以及单次回源上限，可选地接收一组已缓存块（稳定 id + 闭区间）。服务先按
输入顺序计算缓存的可用覆盖（相互重叠时先出现的缓存块优先），再对未覆盖
片段按 max_gap 合并（绝不跨过缓存覆盖）并按 fetch_limit 拆块，输出回源
块以及每个请求范围在回源块 / 缓存块中的切片映射——一个请求范围可以由
多个来源连续拼成，重叠范围可以复用字节并按映射无歧义重组。不提供
cached_blocks 时，行为与旧版完全一致。

POST /assemble 回显 /plan 的 blocks、mappings（以及 cached_blocks），并
分别按块提供 Base64 回源内容与缓存内容；服务严格校验来源 id、边界、缺块
与重复块后，依据切片映射按原 ranges 顺序重组，返回每段范围的 Base64
内容与长度。

POST /secure-request 是 /plan 与 /assemble 的统一鉴权入口：请求携带
operation（plan 或 assemble）、payload（即原接口请求体）、key_id、
timestamp、nonce、signature；服务按固定 JSON 规范化后用环境配置的
HMAC-SHA256 密钥验签，限制时间偏差，并对 key_id+nonce 做窗口内防重放。
验签通过后执行对应操作并原样返回其响应；/plan 与 /assemble 本身不受影响。
"""

from __future__ import annotations

import base64
import binascii
import bisect
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Annotated, Any, Literal, Union

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    BeforeValidator,
    Field,
    StrictInt,
    ValidationError,
    model_validator,
)

app = FastAPI(
    title="Range 回源规划服务",
    description="为对象存储代理规划可合并、带上限、可感知缓存的 HTTP Range 回源。",
)


# ---------------------- /secure-request 鉴权配置 ----------------------


class SecureRequestConfig:
    """从环境变量加载的 HMAC 验签配置（进程级单例）。

    - SECURE_REQUEST_KEYS：逗号分隔的 ``key_id=secret`` 列表，secret 为
      原始 UTF-8 密钥字节（如含特殊字符建议用仅含字母数字/base64 字符的密钥）。
    - SECURE_REQUEST_TIMESTAMP_SKEW：允许的时间偏差（秒），默认 300。
    - SECURE_REQUEST_NONCE_TTL：nonce 保留时长（秒），默认取 2 倍偏差。
    """

    def __init__(self) -> None:
        self.keys: dict[str, bytes] = {}
        self.raw = os.environ.get("SECURE_REQUEST_KEYS", "")
        for item in self.raw.split(","):
            item = item.strip()
            if not item:
                continue
            key_id, sep, secret = item.partition("=")
            if not sep or not key_id or not secret:
                raise RuntimeError(
                    "SECURE_REQUEST_KEYS 格式非法：每项必须为非空的 'key_id=secret'"
                )
            self.keys[key_id] = secret.encode("utf-8")

        skew = int(os.environ.get("SECURE_REQUEST_TIMESTAMP_SKEW", "300"))
        if skew < 1:
            raise RuntimeError("SECURE_REQUEST_TIMESTAMP_SKEW 必须为正整数")
        self.timestamp_skew = skew

        nonce_ttl = int(
            os.environ.get("SECURE_REQUEST_NONCE_TTL", str(max(1, 2 * skew)))
        )
        if nonce_ttl < 1:
            raise RuntimeError("SECURE_REQUEST_NONCE_TTL 必须为正整数")
        self.nonce_ttl = nonce_ttl


secure_config = SecureRequestConfig()

# 进程内 nonce 防重放存储：(key_id, nonce) -> 成功/占用的到期时间戳。
_nonce_lock = threading.Lock()
_nonce_seen: dict[tuple[str, str], float] = {}


def _sweep_nonces(now: float) -> None:
    """清理已过期 nonce（调用方需持有 _nonce_lock）。"""
    expired = [k for k, expiry in _nonce_seen.items() if expiry <= now]
    for k in expired:
        del _nonce_seen[k]


# ----------------------------- 公共类型 -----------------------------


def _validate_cache_id(v: object) -> object:
    """cache_id 允许字符串或整数，但拒绝布尔值与空字符串。"""
    if isinstance(v, bool):
        raise ValueError("cache_id 不得为布尔值")
    if isinstance(v, str) and not v:
        raise ValueError("cache_id 不能为空字符串")
    return v


CacheId = Annotated[Union[str, int], BeforeValidator(_validate_cache_id)]


class CachedBlock(BaseModel):
    """已缓存的字节块：稳定 id + 闭区间 [start, end]。"""

    cache_id: CacheId = Field(..., description="缓存块的稳定 id，用于在 /assemble 中对应内容")
    start: Annotated[int, StrictInt] = Field(..., ge=0, description="缓存起始字节偏移（含）")
    end: Annotated[int, StrictInt] = Field(..., ge=0, description="缓存结束字节偏移（含）")


# ----------------------------- 请求模型 -----------------------------


class IntervalRange(BaseModel):
    """闭区间范围 [start, end]，两端均为包含端点的字节偏移。"""

    type: Literal["interval"]
    start: Annotated[int, StrictInt] = Field(..., ge=0, description="起始字节偏移（含）")
    end: Annotated[int, StrictInt] = Field(..., ge=0, description="结束字节偏移（含）")


class SuffixRange(BaseModel):
    """suffix 范围：对象末尾的 last_n 个字节。"""

    type: Literal["suffix"]
    last_n: Annotated[int, StrictInt] = Field(..., ge=1, description="请求末尾的字节数")


RangeSpec = Annotated[
    Union[IntervalRange, SuffixRange],
    Field(discriminator="type"),
]


class PlanRequest(BaseModel):
    object_length: Annotated[int, StrictInt] = Field(..., ge=0, description="对象总字节长度")
    ranges: list[RangeSpec] = Field(..., min_length=1, description="请求范围列表，可为闭区间或 suffix")
    max_gap: Annotated[int, StrictInt] = Field(..., ge=0, description="允许合并的最大间隙（字节）")
    fetch_limit: Annotated[int, StrictInt] = Field(..., ge=1, description="单次回源上限（字节）")
    cached_blocks: list[CachedBlock] = Field(
        default_factory=list,
        description="可选的已缓存块列表；相互重叠时按输入顺序优先",
    )

    @model_validator(mode="after")
    def _check_unique_cache_ids(self) -> "PlanRequest":
        seen: set[object] = set()
        for cb in self.cached_blocks:
            if cb.cache_id in seen:
                raise ValueError(f"cached_blocks 中 cache_id {cb.cache_id!r} 重复")
            seen.add(cb.cache_id)
        return self


# ----------------------------- 响应模型 -----------------------------


class SliceOut(BaseModel):
    source: Literal["fetch", "cache"] = Field(
        "fetch", description="切片来源：fetch=回源块，cache=缓存块"
    )
    block_index: int | None = Field(None, description="source=fetch 时的回源块编号")
    cache_id: CacheId | None = Field(None, description="source=cache 时的缓存块 id")
    block_start: int = Field(..., description="来源块起始字节偏移（含）")
    block_end: int = Field(..., description="来源块结束字节偏移（含）")
    offset_in_block: int = Field(..., description="切片在来源块中的起始偏移")
    length: int = Field(..., ge=1, description="该切片字节数")


class RangeMapping(BaseModel):
    index: int = Field(..., description="该范围在原请求 ranges 中的下标")
    type: Literal["interval", "suffix"]
    start: int = Field(..., description="规范化后的起始字节偏移（含）")
    end: int = Field(..., description="规范化后的结束字节偏移（含）")
    slices: list[SliceOut] = Field(
        ..., description="在各来源块中的切片映射，按对象偏移连续覆盖整个范围"
    )


class FetchBlock(BaseModel):
    index: int
    start: int = Field(..., description="回源起始字节偏移（含）")
    end: int = Field(..., description="回源结束字节偏移（含）")
    length: int = Field(..., description="回源字节数，不超过 fetch_limit")
    range_header: str = Field(..., description="可直接用于回源的 HTTP Range 头值")


class PlanResponse(BaseModel):
    object_length: int
    blocks: list[FetchBlock]
    mappings: list[RangeMapping]
    cached_blocks: list[CachedBlock] = Field(
        default_factory=list,
        description="本次规划实际引用到的缓存块（原样回显其声明信息）",
    )


# ------------------------ /assemble 请求/响应模型 ------------------------


class BlockContent(BaseModel):
    block_index: int = Field(..., description="回源块编号，对应 blocks[].index")
    data_b64: str = Field(..., description="该回源块的完整回源内容（标准 Base64）")


class CacheContent(BaseModel):
    cache_id: CacheId = Field(..., description="缓存块 id，对应 cached_blocks[].cache_id")
    data_b64: str = Field(..., description="该缓存块的完整内容（标准 Base64）")


class AssembleRequest(BaseModel):
    object_length: Annotated[int, StrictInt] = Field(..., ge=0, description="对象总字节长度")
    blocks: list[FetchBlock] = Field(
        ..., description="回显 /plan 返回的 blocks（全部命中缓存时可为空列表）"
    )
    mappings: list[RangeMapping] = Field(..., min_length=1, description="回显 /plan 返回的 mappings")
    contents: list[BlockContent] = Field(
        ..., description="按块提供的 Base64 回源内容（无回源块时为空列表）"
    )
    cached_blocks: list[CachedBlock] = Field(
        default_factory=list, description="回显 /plan 返回的 cached_blocks"
    )
    cache_contents: list[CacheContent] = Field(
        default_factory=list, description="按缓存块提供的 Base64 缓存内容"
    )


class AssembledRange(BaseModel):
    index: int = Field(..., description="该范围在原请求 ranges 中的下标")
    type: Literal["interval", "suffix"]
    start: int = Field(..., description="规范化后的起始字节偏移（含）")
    end: int = Field(..., description="规范化后的结束字节偏移（含）")
    length: int = Field(..., ge=1, description="重组后的字节数")
    data_b64: str = Field(..., description="重组后的范围内容（标准 Base64）")


class AssembleResponse(BaseModel):
    object_length: int
    ranges: list[AssembledRange] = Field(
        ..., description="按原 ranges 顺序（mappings[].index）排列的重组结果"
    )


# ---------------------- /secure-request 请求模型 ----------------------


class SecureRequest(BaseModel):
    """/secure-request 的签名信封；payload 为 /plan 或 /assemble 的原请求体。"""

    operation: Literal["plan", "assemble"] = Field(
        ..., description="要执行的操作：plan 或 assemble"
    )
    payload: dict[str, Any] = Field(
        ..., description="对应操作的原始请求体（/plan 或 /assemble 的 JSON）"
    )
    key_id: str = Field(..., min_length=1, max_length=128, description="密钥 id")
    timestamp: Annotated[int, StrictInt] = Field(
        ..., ge=0, description="Unix 秒级时间戳"
    )
    nonce: str = Field(
        ..., min_length=1, max_length=128, description="一次性随机串，防重放"
    )
    signature: str = Field(
        ..., min_length=1, description="规范化签名串的 HMAC-SHA256（小写十六进制）"
    )


# ----------------------------- 错误处理 -----------------------------


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """以统一的 422 结构报告字段校验失败（越界、类型错误等）。"""
    return JSONResponse(
        status_code=422,
        content={
            "error": "invalid_request",
            # ctx 中可能携带校验器抛出的异常对象，统一转成字符串以便序列化
            "detail": jsonable_encoder(exc.errors(), custom_encoder={Exception: str}),
        },
    )


class PlanningError(Exception):
    """语义校验失败（范围不可满足等），对应 HTTP 422。"""

    def __init__(self, message: str, range_index: int | None = None):
        self.message = message
        self.range_index = range_index
        super().__init__(message)


@app.exception_handler(PlanningError)
async def planning_error_handler(request: Request, exc: PlanningError):
    return JSONResponse(
        status_code=422,
        content={
            "error": "unsatisfiable",
            "message": exc.message,
            **({"range_index": exc.range_index} if exc.range_index is not None else {}),
        },
    )


class AssemblyError(Exception):
    """组装阶段的语义校验失败（缺块、Base64 无效、越界等），对应 HTTP 422。

    loc 为可定位的字段路径，例如 "contents[2].data_b64"；
    block_index / cache_id / range_index / slice_index 在适用时给出。
    """

    def __init__(
        self,
        message: str,
        loc: str | None = None,
        *,
        block_index: int | None = None,
        cache_id: str | int | None = None,
        range_index: int | None = None,
        slice_index: int | None = None,
        code: str = "assembly_error",
    ):
        self.message = message
        self.loc = loc
        self.block_index = block_index
        self.cache_id = cache_id
        self.range_index = range_index
        self.slice_index = slice_index
        self.code = code
        super().__init__(message)


@app.exception_handler(AssemblyError)
async def assembly_error_handler(request: Request, exc: AssemblyError):
    detail: dict[str, object] = {"message": exc.message}
    if exc.loc is not None:
        detail["loc"] = exc.loc
    if exc.block_index is not None:
        detail["block_index"] = exc.block_index
    if exc.cache_id is not None:
        detail["cache_id"] = exc.cache_id
    if exc.range_index is not None:
        detail["range_index"] = exc.range_index
    if exc.slice_index is not None:
        detail["slice_index"] = exc.slice_index
    return JSONResponse(
        status_code=422,
        content={"error": exc.code, "detail": [detail]},
    )


# ----------------------------- 核心规划逻辑 -----------------------------


def normalize(req: PlanRequest, enforce_fetch_limit: bool) -> list[tuple[int, int]]:
    """把每个范围规范化为闭区间 [start, end]，并拒绝越界或不可满足输入。

    enforce_fetch_limit 为 True 时（无缓存的旧行为），单个范围长度不得
    超过 fetch_limit；缓存感知规划允许一个范围拆到多个回源块，不做此限制。
    """
    normalized: list[tuple[int, int]] = []
    for i, spec in enumerate(req.ranges):
        if spec.type == "interval":
            start, end = spec.start, spec.end
            if end < start:
                raise PlanningError("end 不得小于 start", i)
            if end >= req.object_length:
                raise PlanningError(
                    f"区间 [{start},{end}] 越界：对象长度为 {req.object_length}", i
                )
        else:  # suffix
            # suffix 在对象不足 last_n 字节时按 HTTP 语义回落到整个对象
            start = max(0, req.object_length - spec.last_n)
            end = req.object_length - 1
            if start > end:
                raise PlanningError("空对象无法满足 suffix 范围请求", i)

        if enforce_fetch_limit and end - start + 1 > req.fetch_limit:
            raise PlanningError(
                f"范围 [{start},{end}] 长度 {end - start + 1} 超过单次回源上限 "
                f"{req.fetch_limit}，无法规划",
                i,
            )
        normalized.append((start, end))
    return normalized


def build_plan(
    normalized: list[tuple[int, int]], max_gap: int, fetch_limit: int
) -> tuple[list[tuple[int, int]], list[int]]:
    """贪心合并回源区间（无缓存时的原始逻辑）。

    按起始偏移排序后逐个并入当前块，仅当：
      - 与当前块的间隙 <= max_gap，且
      - 合并后的并集长度 <= fetch_limit
    时才合并；否则另起一个回源块。任何结果块都不会超过 fetch_limit。

    返回 (回源块列表, 每个原范围所属块的编号列表)。
    """
    order = sorted(range(len(normalized)), key=lambda i: normalized[i])
    blocks: list[list[int]] = []  # 每块是 (start, end)
    owner: list[int] = [0] * len(normalized)

    cur_start = cur_end = -1
    cur_index = -1

    for i in order:
        start, end = normalized[i]
        if cur_start == -1:
            cur_start, cur_end, cur_index = start, end, 0
            blocks.append([cur_start, cur_end])
            owner[i] = cur_index
            continue

        gap = start - cur_end - 1
        merged_length = max(cur_end, end) - cur_start + 1
        if gap <= max_gap and merged_length <= fetch_limit:
            # 落入或紧邻当前块：合并（包含关系时块不变）。
            if end > cur_end:
                cur_end = end
                blocks[cur_index][1] = end
        else:
            # 间隙过大或合并后超过上限：另起一个回源块。
            cur_start, cur_end = start, end
            cur_index = len(blocks)
            blocks.append([cur_start, cur_end])
        owner[i] = cur_index

    return [(s, e) for s, e in blocks], owner


# ----------------------------- 缓存覆盖与区间工具 -----------------------------


def subtract_intervals(
    start: int, end: int, intervals: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """从闭区间 [start, end] 中扣除已排序、互不重叠的区间，返回剩余闭区间。"""
    free: list[tuple[int, int]] = []
    cursor = start
    for s, e in intervals:
        if e < cursor:
            continue
        if s > end:
            break
        if s > cursor:
            free.append((cursor, min(s - 1, end)))
        cursor = max(cursor, e + 1)
        if cursor > end:
            break
    if cursor <= end:
        free.append((cursor, end))
    return free


def insert_interval(
    intervals: list[tuple[int, int]], start: int, end: int
) -> list[tuple[int, int]]:
    """把闭区间 [start, end] 并入已排序的互不相交区间列表（重叠或相邻会合并）。"""
    merged: list[tuple[int, int]] = []
    placed = False
    for s, e in intervals:
        if e + 1 < start:
            merged.append((s, e))
        elif end + 1 < s:
            if not placed:
                merged.append((start, end))
                placed = True
            merged.append((s, e))
        else:
            start, end = min(start, s), max(end, e)
    if not placed:
        merged.append((start, end))
    return merged


def compute_coverage(
    cached_blocks: list[CachedBlock],
) -> tuple[list[tuple[int, int, object, int, int]], list[tuple[int, int]]]:
    """按输入顺序计算缓存的可用覆盖：相互重叠时先出现的缓存块优先。

    返回 (覆盖条目, 覆盖区间)：
      - 覆盖条目为 (start, end, cache_id, block_start, block_end)，按起始偏移
        排序；block_start/block_end 是所属缓存块声明的完整区间，用于切片定位；
      - 覆盖区间为排序后的 (start, end) 列表，用于扣除与相交判断。
    """
    claimed: list[tuple[int, int]] = []
    entries: list[tuple[int, int, object, int, int]] = []
    for cb in cached_blocks:
        # 只把尚未被更早缓存块占据的部分记为该块的可用覆盖
        for fs, fe in subtract_intervals(cb.start, cb.end, claimed):
            entries.append((fs, fe, cb.cache_id, cb.start, cb.end))
        claimed = insert_interval(claimed, cb.start, cb.end)
    entries.sort(key=lambda item: (item[0], item[1]))
    return entries, [(s, e) for s, e, *_ in entries]


def has_coverage(
    cov: list[tuple[int, int]], cov_starts: list[int], start: int, end: int
) -> bool:
    """闭区间 [start, end]（start <= end）是否与任一缓存覆盖区间相交。"""
    i = bisect.bisect_right(cov_starts, end) - 1
    return i >= 0 and cov[i][1] >= start


def merge_fragments(
    fragments: list[tuple[int, int]],
    max_gap: int,
    cov: list[tuple[int, int]],
    cov_starts: list[int],
) -> list[tuple[int, int]]:
    """把未覆盖片段按 max_gap 贪心合并，但合并不得跨过任何缓存覆盖。"""
    merged: list[list[int]] = []
    for fs, fe in fragments:  # 调用前已按 (start, end) 排序
        if merged:
            prev_end = merged[-1][1]
            gap = fs - prev_end - 1
            if gap <= max_gap and (
                gap < 1 or not has_coverage(cov, cov_starts, prev_end + 1, fs - 1)
            ):
                # 间隙足够小且不含缓存覆盖：并入当前段（包含关系时段不变）。
                if fe > prev_end:
                    merged[-1][1] = fe
                continue
        merged.append([fs, fe])
    return [(s, e) for s, e in merged]


def split_blocks(
    merged: list[tuple[int, int]], fetch_limit: int
) -> list[tuple[int, int]]:
    """把合并后的回源段按 fetch_limit 拆成不超过上限的回源块。"""
    blocks: list[tuple[int, int]] = []
    for start, end in merged:
        cursor = start
        while cursor <= end:
            block_end = min(end, cursor + fetch_limit - 1)
            blocks.append((cursor, block_end))
            cursor = block_end + 1
    return blocks


# ----------------------------- /plan -----------------------------


def plan_without_cache(req: PlanRequest) -> PlanResponse:
    """不含缓存块时的原始规划逻辑（保持旧行为与旧约束）。"""
    normalized = normalize(req, enforce_fetch_limit=True)
    block_tuples, owner = build_plan(normalized, req.max_gap, req.fetch_limit)

    fetch_blocks = [
        FetchBlock(
            index=i,
            start=s,
            end=e,
            length=e - s + 1,
            range_header=f"bytes={s}-{e}",
        )
        for i, (s, e) in enumerate(block_tuples)
    ]

    mappings: list[RangeMapping] = []
    for i, (start, end) in enumerate(normalized):
        block_index = owner[i]
        bstart, bend = block_tuples[block_index]
        # 排序合并保证该范围完整包含在其所属块中，映射只有一个切片。
        slices = [
            SliceOut(
                source="fetch",
                block_index=block_index,
                block_start=bstart,
                block_end=bend,
                offset_in_block=start - bstart,
                length=end - start + 1,
            )
        ]
        mappings.append(
            RangeMapping(
                index=i,
                type=req.ranges[i].type,
                start=start,
                end=end,
                slices=slices,
            )
        )

    return PlanResponse(
        object_length=req.object_length,
        blocks=fetch_blocks,
        mappings=mappings,
        cached_blocks=[],
    )


def plan_with_cache(req: PlanRequest) -> PlanResponse:
    """缓存感知规划：先算可用覆盖，再合并未覆盖片段，最后按上限拆块。"""
    for cb in req.cached_blocks:
        if cb.end < cb.start:
            raise PlanningError(
                f"缓存块 {cb.cache_id!r} 的区间 [{cb.start},{cb.end}] 非法："
                "end 不得小于 start"
            )
        if cb.end >= req.object_length:
            raise PlanningError(
                f"缓存块 {cb.cache_id!r} [{cb.start},{cb.end}] 越界："
                f"对象长度为 {req.object_length}"
            )

    # 缓存命中部分可复用，单个范围不再受 fetch_limit 整体限制
    normalized = normalize(req, enforce_fetch_limit=False)
    coverage, cov_intervals = compute_coverage(req.cached_blocks)
    cov_starts = [s for s, _ in cov_intervals]

    # 1. 每个范围扣除缓存覆盖，得到未覆盖片段
    fragments: list[tuple[int, int]] = []
    for start, end in normalized:
        fragments.extend(subtract_intervals(start, end, cov_intervals))
    fragments.sort()

    # 2. 片段按 max_gap 合并（不跨过缓存覆盖），再按 fetch_limit 拆块
    block_tuples = split_blocks(
        merge_fragments(fragments, req.max_gap, cov_intervals, cov_starts),
        req.fetch_limit,
    )

    fetch_blocks = [
        FetchBlock(
            index=i,
            start=s,
            end=e,
            length=e - s + 1,
            range_header=f"bytes={s}-{e}",
        )
        for i, (s, e) in enumerate(block_tuples)
    ]

    # 3. 缓存覆盖与回源块共同组成有序来源段，恰好拼接每个请求范围
    segments: list[tuple[int, int, str, object, int, int]] = []
    for cs, ce, cid, bs, be in coverage:
        segments.append((cs, ce, "cache", cid, bs, be))
    for i, (bs, be) in enumerate(block_tuples):
        segments.append((bs, be, "fetch", i, bs, be))
    segments.sort(key=lambda seg: (seg[0], seg[1]))

    mappings: list[RangeMapping] = []
    used_cache_ids: set[object] = set()
    for i, (start, end) in enumerate(normalized):
        slices: list[SliceOut] = []
        for ss, se, kind, ref, bs, be in segments:
            if se < start or ss > end:
                continue
            a, b = max(start, ss), min(end, se)
            if a > b:
                continue
            if kind == "cache":
                used_cache_ids.add(ref)
            slices.append(
                SliceOut(
                    source=kind,  # type: ignore[arg-type]
                    block_index=ref if kind == "fetch" else None,
                    cache_id=ref if kind == "cache" else None,
                    block_start=bs,
                    block_end=be,
                    offset_in_block=a - bs,
                    length=b - a + 1,
                )
            )
        mappings.append(
            RangeMapping(
                index=i,
                type=req.ranges[i].type,
                start=start,
                end=end,
                slices=slices,
            )
        )

    used_cached_blocks = [
        cb for cb in req.cached_blocks if cb.cache_id in used_cache_ids
    ]
    return PlanResponse(
        object_length=req.object_length,
        blocks=fetch_blocks,
        mappings=mappings,
        cached_blocks=used_cached_blocks,
    )


@app.post("/plan", response_model=PlanResponse)
def plan(req: PlanRequest) -> PlanResponse:
    if not req.cached_blocks:
        return plan_without_cache(req)
    return plan_with_cache(req)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


# ----------------------------- 组装逻辑 -----------------------------


def decode_b64(loc: str, raw: str, **ctx: object) -> bytes:
    """严格按标准 Base64（含正确的 = 填充）解码单个来源块内容。"""
    if len(raw) % 4 != 0:
        raise AssemblyError(
            "Base64 长度不是 4 的倍数，缺少填充或包含非法字符",
            loc,
            code="invalid_base64",
            **ctx,
        )
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AssemblyError(
            f"Base64 解码失败：{exc}",
            loc,
            code="invalid_base64",
            **ctx,
        )


@app.post("/assemble", response_model=AssembleResponse)
def assemble(req: AssembleRequest) -> AssembleResponse:
    # 1. 校验 blocks：编号唯一、区间合法、不超过对象长度。
    declared: dict[int, FetchBlock] = {}
    for pos, block in enumerate(req.blocks):
        if block.index < 0:
            raise AssemblyError(
                "回源块编号不得为负",
                f"blocks[{pos}].index",
                block_index=block.index,
                code="invalid_block",
            )
        if block.end < block.start:
            raise AssemblyError(
                f"回源块 [{block.start},{block.end}] 非法：end 不得小于 start",
                f"blocks[{pos}]",
                block_index=block.index,
                code="invalid_block",
            )
        if block.end >= req.object_length:
            raise AssemblyError(
                f"回源块 [{block.start},{block.end}] 越界：对象长度为 {req.object_length}",
                f"blocks[{pos}]",
                block_index=block.index,
                code="block_out_of_bounds",
            )
        if block.length != block.end - block.start + 1:
            raise AssemblyError(
                f"声明长度 {block.length} 与区间 [{block.start},{block.end}] "
                f"应有的 {block.end - block.start + 1} 字节不符",
                f"blocks[{pos}].length",
                block_index=block.index,
                code="invalid_block",
            )
        if block.index in declared:
            raise AssemblyError(
                f"回源块编号 {block.index} 重复",
                f"blocks[{pos}].index",
                block_index=block.index,
                code="duplicate_block",
            )
        declared[block.index] = block

    # 2. 校验 contents：索引唯一且与 blocks 一一对应，再解码并核对字节数。
    decoded: dict[int, bytes] = {}
    for pos, item in enumerate(req.contents):
        if item.block_index < 0:
            raise AssemblyError(
                "内容块编号不得为负",
                f"contents[{pos}].block_index",
                block_index=item.block_index,
                code="invalid_block",
            )
        if item.block_index in decoded:
            raise AssemblyError(
                f"回源块 {item.block_index} 的内容被重复提供",
                f"contents[{pos}].block_index",
                block_index=item.block_index,
                code="duplicate_block_content",
            )
        block = declared.get(item.block_index)
        if block is None:
            raise AssemblyError(
                f"提供了 blocks 中不存在的多余回源块 {item.block_index}",
                f"contents[{pos}].block_index",
                block_index=item.block_index,
                code="unexpected_block",
            )
        data = decode_b64(
            f"contents[{pos}].data_b64", item.data_b64, block_index=item.block_index
        )
        if len(data) != block.length:
            raise AssemblyError(
                f"块 {block.index} 解码后 {len(data)} 字节，"
                f"与声明长度 {block.length} 不符",
                f"contents[{pos}].data_b64",
                block_index=block.index,
                code="block_length_mismatch",
            )
        decoded[item.block_index] = data

    missing = [idx for idx in declared if idx not in decoded]
    if missing:
        missing.sort()
        raise AssemblyError(
            f"缺少 {len(missing)} 个回源块的内容：{missing}",
            "contents",
            block_index=missing[0],
            code="missing_block",
        )

    # 2b. 校验 cached_blocks：id 唯一、区间合法、不超过对象长度。
    declared_cache: dict[object, CachedBlock] = {}
    for pos, cb in enumerate(req.cached_blocks):
        if cb.end < cb.start:
            raise AssemblyError(
                f"缓存块 {cb.cache_id!r} 的区间 [{cb.start},{cb.end}] 非法："
                "end 不得小于 start",
                f"cached_blocks[{pos}]",
                cache_id=cb.cache_id,
                code="invalid_cache",
            )
        if cb.end >= req.object_length:
            raise AssemblyError(
                f"缓存块 {cb.cache_id!r} [{cb.start},{cb.end}] 越界："
                f"对象长度为 {req.object_length}",
                f"cached_blocks[{pos}]",
                cache_id=cb.cache_id,
                code="cache_out_of_bounds",
            )
        if cb.cache_id in declared_cache:
            raise AssemblyError(
                f"缓存块 id {cb.cache_id!r} 重复",
                f"cached_blocks[{pos}].cache_id",
                cache_id=cb.cache_id,
                code="duplicate_cache",
            )
        declared_cache[cb.cache_id] = cb

    # 2c. 校验 cache_contents：id 唯一且与 cached_blocks 一一对应，再解码核对字节数。
    decoded_cache: dict[object, bytes] = {}
    for pos, item in enumerate(req.cache_contents):
        if item.cache_id in decoded_cache:
            raise AssemblyError(
                f"缓存块 {item.cache_id!r} 的内容被重复提供",
                f"cache_contents[{pos}].cache_id",
                cache_id=item.cache_id,
                code="duplicate_cache_content",
            )
        cb = declared_cache.get(item.cache_id)
        if cb is None:
            raise AssemblyError(
                f"提供了 cached_blocks 中不存在的缓存块 {item.cache_id!r} 的内容",
                f"cache_contents[{pos}].cache_id",
                cache_id=item.cache_id,
                code="unexpected_cache",
            )
        data = decode_b64(
            f"cache_contents[{pos}].data_b64", item.data_b64, cache_id=item.cache_id
        )
        cache_length = cb.end - cb.start + 1
        if len(data) != cache_length:
            raise AssemblyError(
                f"缓存块 {cb.cache_id!r} 解码后 {len(data)} 字节，"
                f"与声明长度 {cache_length} 不符",
                f"cache_contents[{pos}].data_b64",
                cache_id=cb.cache_id,
                code="cache_length_mismatch",
            )
        decoded_cache[item.cache_id] = data

    missing_cache = [cid for cid in declared_cache if cid not in decoded_cache]
    if missing_cache:
        raise AssemblyError(
            f"缺少 {len(missing_cache)} 个缓存块的内容：{missing_cache}",
            "cache_contents",
            cache_id=missing_cache[0],
            code="missing_cache",
        )

    # 3. 校验 mappings：下标连续且覆盖 0..N-1，切片不越界且恰好拼接成原范围。
    mapping_pos: dict[int, int] = {}
    for pos, mapping in enumerate(req.mappings):
        if mapping.index < 0:
            raise AssemblyError(
                "映射下标不得为负",
                f"mappings[{pos}].index",
                range_index=mapping.index,
                code="invalid_mapping_index",
            )
        if mapping.index in mapping_pos:
            raise AssemblyError(
                f"范围下标 {mapping.index} 在 mappings 中重复",
                f"mappings[{pos}].index",
                range_index=mapping.index,
                code="duplicate_mapping_index",
            )
        mapping_pos[mapping.index] = pos

    n = len(req.mappings)
    if set(mapping_pos) != set(range(n)):
        extra = sorted(i for i in mapping_pos if i >= n)
        missing_idx = sorted(set(range(n)) - set(mapping_pos))
        detail = f"mappings 下标应为 0..{n - 1} 的全排列"
        if missing_idx:
            detail += f"，缺少下标 {missing_idx}"
        if extra:
            detail += f"，存在多余下标 {extra}"
        raise AssemblyError(detail, "mappings", code="invalid_mapping_index")

    ordered_mappings = sorted(req.mappings, key=lambda m: m.index)
    for mapping in ordered_mappings:
        mpos = mapping_pos[mapping.index]
        if mapping.end < mapping.start:
            raise AssemblyError(
                f"范围 [{mapping.start},{mapping.end}] 非法：end 不得小于 start",
                f"mappings[{mpos}]",
                range_index=mapping.index,
                code="invalid_mapping",
            )
        if mapping.end >= req.object_length:
            raise AssemblyError(
                f"范围 [{mapping.start},{mapping.end}] 越界："
                f"对象长度为 {req.object_length}",
                f"mappings[{mpos}]",
                range_index=mapping.index,
                code="mapping_out_of_bounds",
            )
        if not mapping.slices:
            raise AssemblyError(
                "切片列表不能为空",
                f"mappings[{mpos}].slices",
                range_index=mapping.index,
                code="empty_slices",
            )

        cursor = mapping.start
        for slice_pos, sl in enumerate(mapping.slices):
            loc_base = f"mappings[{mpos}].slices[{slice_pos}]"
            # 解析切片来源，并核对来源字段组合与声明的块区间
            if sl.source == "fetch":
                if sl.block_index is None or sl.cache_id is not None:
                    raise AssemblyError(
                        "source=fetch 的切片必须携带 block_index 且不得携带 cache_id",
                        loc_base,
                        range_index=mapping.index,
                        slice_index=slice_pos,
                        code="invalid_slice",
                    )
                block = declared.get(sl.block_index)
                if block is None:
                    raise AssemblyError(
                        f"切片引用了不存在的回源块 {sl.block_index}",
                        f"{loc_base}.block_index",
                        range_index=mapping.index,
                        slice_index=slice_pos,
                        code="unknown_block_reference",
                    )
                src_start, src_end, src_length = block.start, block.end, block.length
                src_ctx: dict[str, object] = {"block_index": block.index}
            else:  # cache
                if sl.cache_id is None or sl.block_index is not None:
                    raise AssemblyError(
                        "source=cache 的切片必须携带 cache_id 且不得携带 block_index",
                        loc_base,
                        range_index=mapping.index,
                        slice_index=slice_pos,
                        code="invalid_slice",
                    )
                cb = declared_cache.get(sl.cache_id)
                if cb is None:
                    raise AssemblyError(
                        f"切片引用了未声明的缓存块 {sl.cache_id!r}",
                        f"{loc_base}.cache_id",
                        cache_id=sl.cache_id,
                        range_index=mapping.index,
                        slice_index=slice_pos,
                        code="unknown_cache_reference",
                    )
                src_start, src_end = cb.start, cb.end
                src_length = src_end - src_start + 1
                src_ctx = {"cache_id": cb.cache_id}

            if sl.block_start != src_start or sl.block_end != src_end:
                raise AssemblyError(
                    f"切片记录的来源块区间 [{sl.block_start},{sl.block_end}] "
                    f"与声明的 [{src_start},{src_end}] 不一致",
                    loc_base,
                    range_index=mapping.index,
                    slice_index=slice_pos,
                    code="slice_block_mismatch",
                    **src_ctx,
                )
            if sl.offset_in_block < 0 or sl.length < 1:
                raise AssemblyError(
                    "切片的 offset_in_block 不得为负且 length 至少为 1",
                    loc_base,
                    range_index=mapping.index,
                    slice_index=slice_pos,
                    code="invalid_slice",
                    **src_ctx,
                )
            if sl.offset_in_block + sl.length > src_length:
                raise AssemblyError(
                    f"切片 offset={sl.offset_in_block}, length={sl.length} "
                    f"超出来源块的 {src_length} 字节",
                    loc_base,
                    range_index=mapping.index,
                    slice_index=slice_pos,
                    code="slice_out_of_bounds",
                    **src_ctx,
                )
            expected_offset = cursor - src_start
            if sl.offset_in_block != expected_offset:
                raise AssemblyError(
                    f"切片应从来源块的偏移 {expected_offset} 开始"
                    f"（衔接对象偏移 {cursor}），实际偏移为 {sl.offset_in_block}，"
                    "切片无法连续覆盖该范围",
                    loc_base,
                    range_index=mapping.index,
                    slice_index=slice_pos,
                    code="slice_misaligned",
                    **src_ctx,
                )
            cursor += sl.length

        expected_length = mapping.end - mapping.start + 1
        assembled_length = cursor - mapping.start
        if assembled_length != expected_length:
            raise AssemblyError(
                f"范围 {mapping.index} 的切片总长 {assembled_length} 字节，"
                f"与声明的 {expected_length} 字节不符",
                f"mappings[{mpos}].slices",
                range_index=mapping.index,
                code="assembly_length_mismatch",
            )

    # 4. 全部通过：按切片从解码字节中取材，按原 ranges 顺序拼接。
    results: list[AssembledRange] = []
    for mapping in ordered_mappings:
        parts = []
        for sl in mapping.slices:
            data = (
                decoded[sl.block_index]
                if sl.source == "fetch"
                else decoded_cache[sl.cache_id]
            )
            parts.append(data[sl.offset_in_block : sl.offset_in_block + sl.length])
        payload = b"".join(parts)
        results.append(
            AssembledRange(
                index=mapping.index,
                type=mapping.type,
                start=mapping.start,
                end=mapping.end,
                length=len(payload),
                data_b64=base64.b64encode(payload).decode("ascii"),
            )
        )

    return AssembleResponse(object_length=req.object_length, ranges=results)


# ----------------------------- /secure-request -----------------------------


def canonical_signing_object(
    operation: str,
    payload: dict[str, Any],
    key_id: str,
    timestamp: int,
    nonce: str,
) -> dict[str, Any]:
    """构造固定字段集合的签名对象（不含 signature 本身）。"""
    return {
        "operation": operation,
        "payload": payload,
        "key_id": key_id,
        "timestamp": timestamp,
        "nonce": nonce,
    }


def canonical_json(obj: Any) -> bytes:
    """固定 JSON 规范化：键按字典序排序、无多余空白、UTF-8、ensure_ascii=False。

    签名双方必须使用完全一致的规范化结果。不支持 NaN/Infinity
    （Python 的 json 默认 allow_nan 会输出非标准 JSON，这里显式拒绝）。
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _auth_error(
    code: str, message: str, *, status_code: int, **extra: Any
) -> JSONResponse:
    """构造可定位的 401/409/503 鉴权错误响应。"""
    return JSONResponse(
        status_code=status_code,
        content={"error": code, "message": message, **extra},
    )


@app.post("/secure-request")
def secure_request(raw: SecureRequest) -> JSONResponse:
    """统一鉴权入口：验签 + 时间窗 + nonce 防重放后执行 plan/assemble。

    成功时原样返回对应操作的响应（HTTP 200）。鉴权失败返回 401，
    nonce 重放返回 409，payload 语义错误沿用对应操作的 422 结构。
    """
    # 0. 服务端未配置任何密钥：明确报错，而不是静默放行。
    if not secure_config.keys:
        return _auth_error(
            "keys_not_configured",
            "服务端未配置 SECURE_REQUEST_KEYS，/secure-request 不可用",
            status_code=503,
        )

    # 1. 时间偏差校验（先于密钥查找/验签，过期请求一律拒绝）。
    now = time.time()
    skew = now - raw.timestamp
    if abs(skew) > secure_config.timestamp_skew:
        return _auth_error(
            "timestamp_skew",
            f"时间戳偏差 {skew:+.0f}s 超出允许范围 "
            f"±{secure_config.timestamp_skew}s",
            status_code=401,
            server_time=int(now),
            max_skew_seconds=secure_config.timestamp_skew,
        )

    # 2. key_id 未知：明确报错（不与签名失败混淆，便于客户端定位）。
    secret = secure_config.keys.get(raw.key_id)
    if secret is None:
        return _auth_error(
            "unknown_key_id",
            f"未知的 key_id：{raw.key_id!r}",
            status_code=401,
            key_id=raw.key_id,
        )

    # 3. 固定 JSON 规范化后重算 HMAC-SHA256，常量时间比较。
    try:
        signing_bytes = canonical_json(
            canonical_signing_object(
                raw.operation, raw.payload, raw.key_id, raw.timestamp, raw.nonce
            )
        )
    except (TypeError, ValueError):
        return _auth_error(
            "invalid_signing_payload",
            "payload 无法规范化为 JSON（包含 NaN/Infinity 或不可序列化值）",
            status_code=422,
        )
    expected = hmac.new(secret, signing_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, raw.signature.lower()):
        return _auth_error(
            "invalid_signature",
            "签名校验失败：signature 与规范化签名串的 HMAC-SHA256 不符",
            status_code=401,
        )

    # 4. nonce 防重放：同一 key_id+nonce 在有效窗口内只能成功一次。
    #    先占位；若后续 payload 校验或操作执行失败则回滚，避免失败请求
    #    白白消耗 nonce（只有真正成功的请求才永久占用）。
    nonce_key = (raw.key_id, raw.nonce)
    with _nonce_lock:
        _sweep_nonces(now)
        if nonce_key in _nonce_seen:
            return _auth_error(
                "nonce_replayed",
                f"key_id={raw.key_id!r} 的 nonce 已在有效窗口内使用过",
                status_code=409,
                key_id=raw.key_id,
            )
        _nonce_seen[nonce_key] = now + secure_config.nonce_ttl

    try:
        # 5. 鉴权通过：用 payload 校验对应操作的模型（失败返回带 payload
        #    路径的 422），再执行原有逻辑并原样序列化其响应。
        try:
            if raw.operation == "plan":
                result = plan(PlanRequest.model_validate(raw.payload))
            else:
                result = assemble(AssembleRequest.model_validate(raw.payload))
        except ValidationError as exc:
            errors = exc.errors()
            for err in errors:
                err["loc"] = ("payload",) + tuple(err.get("loc", ()))
            response = JSONResponse(
                status_code=422,
                content={
                    "error": "invalid_request",
                    "detail": jsonable_encoder(
                        errors, custom_encoder={Exception: str}
                    ),
                },
            )
        else:
            response = JSONResponse(
                status_code=200, content=jsonable_encoder(result)
            )
    except BaseException:
        # 业务异常（PlanningError/AssemblyError 等 422）或其他异常：
        # 本次请求未成功，释放 nonce 占位，允许客户端修正后用同一 nonce 重试。
        with _nonce_lock:
            _nonce_seen.pop(nonce_key, None)
        raise

    # payload 校验失败（未执行任何操作）：同样回滚 nonce 占位。
    if response.status_code != 200:
        with _nonce_lock:
            _nonce_seen.pop(nonce_key, None)
    return response
