# Range 回源规划与重组服务

为对象存储代理规划 HTTP Range 回源的 FastAPI 服务：

- `POST /plan`：规范化闭区间 / suffix 范围，可选接收已缓存块（`cached_blocks`）。
  先按输入顺序计算缓存的可用覆盖，再对未覆盖片段按最大间隙合并（绝不跨过缓存
  覆盖）、按单次回源上限拆块，返回回源块以及每个原范围在回源块 / 缓存块中的
  切片映射——一个范围可以由多个来源连续拼成。
- `POST /assemble`：回显 `/plan` 的 `blocks`、`mappings`（以及 `cached_blocks`），
  并分别按块提供 Base64 回源内容与缓存内容；服务严格校验来源 id、边界、缺块
  与重复块后，依据切片映射按原 ranges 顺序重组，返回每段范围的 Base64 内容与长度。
- `POST /secure-request`：上述两个操作的**统一鉴权入口**。请求携带 `operation`
  （`plan` 或 `assemble`）、`payload`（原接口请求体）以及 `key_id` / `timestamp`
  / `nonce` / `signature`；服务按固定 JSON 规范化后用环境配置的 HMAC-SHA256
  密钥验签、限制时间偏差，并对 `key_id+nonce` 做有效窗口内防重放。验签通过后
  执行对应操作并**原样返回该操作的响应**。`/plan` 与 `/assemble` 行为不受影响。

## Docker 一键启动

需要 Docker 20.10+（支持 Compose v2）。在仓库根目录执行：

```
docker compose up --build -d
```

首次会构建镜像（Python 3.12 slim）并在后台启动；查看日志与停止：

```
docker compose logs -f
docker compose down
```

不带 `-d` 可在前台运行。健康检查就绪后，服务监听
http://127.0.0.1:8080 （接口文档：http://127.0.0.1:8080/docs ）。

不使用 Compose 时也可以直接用 Docker：

```
docker build -t range-planner:latest .
docker run --rm -p 127.0.0.1:8080:8080 range-planner:latest
```

## 配置

`/plan` 与 `/assemble` 无需任何配置。`/secure-request` 通过以下环境变量配置：

| 环境变量 | 必需 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `SECURE_REQUEST_KEYS` | 使用 `/secure-request` 时必需 | 空 | 逗号分隔的 `key_id=secret` 列表，`secret` 为原始 UTF-8 密钥字节（建议使用 32 字节随机值的 hex/base64 文本，避免出现 `,` 与 `=`） |
| `SECURE_REQUEST_TIMESTAMP_SKEW` | 否 | `300` | 请求 `timestamp` 与服务端时间允许的最大偏差（秒） |
| `SECURE_REQUEST_NONCE_TTL` | 否 | `600`（2 倍偏差） | 同一 `key_id+nonce` 的防重放保留窗口（秒），应不小于时间偏差 |

未设置 `SECURE_REQUEST_KEYS`（或为空）时，`/plan`、`/assemble` 仍正常工作，
但 `/secure-request` 返回 `503 keys_not_configured`。密钥配置格式非法（启动时
解析失败）会导致服务直接启动失败，避免带错误配置上线。

可复制 `.env.example` 为 `.env` 后修改；`docker compose` 会自动读取同目录
`.env`。也可以直接用 `-e` 注入：

```
docker run --rm -p 127.0.0.1:8080:8080 \
  -e SECURE_REQUEST_KEYS='demo-key=0123456789abcdef0123456789abcdef' \
  range-planner:latest
```

如需更改对外端口，修改 `docker-compose.yml` 中的端口映射
`127.0.0.1:8080:8080`（容器内固定监听 8080）。

## 接口

### `GET /healthz`

返回 `{"status": "ok"}`，供容器健康检查使用。

### `POST /plan`

请求示例（不带缓存，行为与旧版一致）：

```json
{
  "object_length": 256,
  "ranges": [
    {"type": "interval", "start": 0, "end": 99},
    {"type": "suffix", "last_n": 16}
  ],
  "max_gap": 8,
  "fetch_limit": 128
}
```

响应中的 `blocks` 为合并后的回源块（含可直接使用的 `range_header`），
`mappings` 为每个原范围（按 `index` 对应输入下标）在块中的切片映射。

#### 缓存感知规划（可选 `cached_blocks`）

如果调用方本地已缓存了对象的某些字节，可以通过 `cached_blocks` 声明，
每项为稳定 id（字符串或整数，请求内唯一）加闭区间：

```json
{
  "object_length": 256,
  "ranges": [
    {"type": "interval", "start": 0, "end": 99},
    {"type": "suffix", "last_n": 16}
  ],
  "max_gap": 8,
  "fetch_limit": 128,
  "cached_blocks": [
    {"cache_id": "cdn-a", "start": 40, "end": 59}
  ]
}
```

规划规则：

1. **可用覆盖**：多个缓存块相互重叠时按输入顺序优先——先出现的缓存块占据
   重叠部分，后出现的只获得尚未被占据的剩余区间；
2. **未覆盖片段合并**：各范围扣除缓存覆盖后得到未覆盖片段，间隙
   `<= max_gap` 的相邻片段合并为一个回源段，但合并**不得跨过缓存覆盖**
   （间隙中含有缓存字节时绝不合并，避免重复回源）；
3. **按上限拆块**：合并后的回源段按 `fetch_limit` 拆成若干回源块，每块
   不超过上限。因此提供 `cached_blocks` 后，单个范围允许超过
   `fetch_limit`（会被拆到多个回源块），不再报 `unsatisfiable`；
4. **切片来源**：`mappings[].slices[]` 用 `source` 标明来源——`"fetch"`
   （携带 `block_index`）或 `"cache"`（携带 `cache_id`）。一个范围的多个
   切片按对象偏移顺序连续覆盖整个范围，可以横跨缓存块与多个回源块。

上面的请求会得到 3 个回源块 `[0,39]`、`[60,99]`、`[240,255]`，其中范围 0
的切片依次为 `fetch(块0)` → `cache(cdn-a)` → `fetch(块1)`：

```json
{
  "object_length": 256,
  "blocks": [
    {"index": 0, "start": 0, "end": 39, "length": 40, "range_header": "bytes=0-39"},
    {"index": 1, "start": 60, "end": 99, "length": 40, "range_header": "bytes=60-99"},
    {"index": 2, "start": 240, "end": 255, "length": 16, "range_header": "bytes=240-255"}
  ],
  "mappings": [
    {
      "index": 0,
      "type": "interval",
      "start": 0,
      "end": 99,
      "slices": [
        {"source": "fetch", "block_index": 0, "cache_id": null,
         "block_start": 0, "block_end": 39, "offset_in_block": 0, "length": 40},
        {"source": "cache", "block_index": null, "cache_id": "cdn-a",
         "block_start": 40, "block_end": 59, "offset_in_block": 0, "length": 20},
        {"source": "fetch", "block_index": 1, "cache_id": null,
         "block_start": 60, "block_end": 99, "offset_in_block": 0, "length": 40}
      ]
    },
    {
      "index": 1,
      "type": "suffix",
      "start": 240,
      "end": 255,
      "slices": [
        {"source": "fetch", "block_index": 2, "cache_id": null,
         "block_start": 240, "block_end": 255, "offset_in_block": 0, "length": 16}
      ]
    }
  ],
  "cached_blocks": [
    {"cache_id": "cdn-a", "start": 40, "end": 59}
  ]
}
```

响应中的 `cached_blocks` 只回显本次规划**实际引用到**的缓存块（未命中任何
范围的缓存块不会出现）。若所有范围都命中缓存，`blocks` 为空列表。

### `POST /assemble`

请求体把 `/plan` 的返回原样回显，并在 `contents` 中为**每个**回源块提供其
完整回源内容（标准 Base64，含 `=` 填充）；若规划引用了缓存块，还需回显
`cached_blocks` 并在 `cache_contents` 中为**每个**缓存块提供完整缓存内容：

```json
{
  "object_length": 256,
  "blocks": [
    {"index": 0, "start": 0, "end": 39, "length": 40, "range_header": "bytes=0-39"},
    {"index": 1, "start": 60, "end": 99, "length": 40, "range_header": "bytes=60-99"},
    {"index": 2, "start": 240, "end": 255, "length": 16, "range_header": "bytes=240-255"}
  ],
  "mappings": [ ... ],
  "contents": [
    {"block_index": 0, "data_b64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJw=="},
    {"block_index": 1, "data_b64": "PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw=="},
    {"block_index": 2, "data_b64": "8PHy8/T19vf4+fr7/P3+/w=="}
  ],
  "cached_blocks": [
    {"cache_id": "cdn-a", "start": 40, "end": 59}
  ],
  "cache_contents": [
    {"cache_id": "cdn-a", "data_b64": "KCkqKywtLi8wMTIzNDU2Nzg5Ojs="}
  ]
}
```

校验规则（任一不满足都返回 `422`）：

1. `blocks[].index` 唯一、区间合法、`length == end - start + 1` 且不越界；
2. `contents[].block_index` 唯一，且与 `blocks` 一一对应——缺块、重复提供、
   提供多余块都会被拒绝；
3. `cached_blocks[].cache_id` 唯一、区间合法且不越界；`cache_contents[].cache_id`
   唯一，且与 `cached_blocks` 一一对应——缺块、重复提供、提供未声明的 id
   都会被拒绝；
4. `data_b64` 必须是合法的标准 Base64，解码字节数必须等于该来源块的声明长度；
5. `mappings[].index` 必须恰好覆盖 `0..N-1`（对应原 ranges 顺序，不可重复或缺失）；
6. 每个切片的来源必须合法：`source=fetch` 携带 `block_index` 且引用存在的
   回源块，`source=cache` 携带 `cache_id` 且引用已声明的缓存块；切片记录的
   `block_start/block_end` 与来源块一致，`offset_in_block + length` 不得超出
   来源块长度；
7. 切片必须从范围起点开始连续拼接（可横跨多个来源），且总长度等于
   `end - start + 1`。

全部命中缓存时 `blocks` 与 `contents` 传空列表即可。成功响应按原 ranges
顺序（`mappings[].index`）返回每段内容：

```json
{
  "object_length": 256,
  "ranges": [
    {
      "index": 0,
      "type": "interval",
      "start": 0,
      "end": 99,
      "length": 100,
      "data_b64": "..."
    }
  ]
}
```

典型调用流程：先请求 `/plan`，按 `blocks[].range_header` 发起实际回源，
把每块响应体做 Base64 编码；命中缓存的部分直接从本地缓存读取对应
`cached_blocks` 的字节并做 Base64 编码；最后连同 `blocks`、`mappings`、
`cached_blocks` 一起提交给 `/assemble`，即可取回与原请求 ranges 一一对应
的字节内容。

### `POST /secure-request`

`/plan` 与 `/assemble` 的统一鉴权入口。`payload` 字段就是对应操作的原始
请求体（与直接调用 `/plan`、`/assemble` 完全一致）：

```json
{
  "operation": "plan",
  "payload": {
    "object_length": 256,
    "ranges": [
      {"type": "interval", "start": 0, "end": 99},
      {"type": "suffix", "last_n": 16}
    ],
    "max_gap": 8,
    "fetch_limit": 128
  },
  "key_id": "demo-key",
  "timestamp": 1758537600,
  "nonce": "7f3c9a1e0b644f0d8a2e5c1b9a7e0d33",
  "signature": "小写十六进制的 HMAC-SHA256"
}
```

成功后**原样返回** `operation` 对应操作的响应（与直接调用 `/plan` 或
`/assemble` 的 JSON 完全相同）。可运行的完整示例（签名 + 调用 plan + 回源
模拟 + assemble 重组校验）见
[`examples/secure_request_example.py`](examples/secure_request_example.py)：

```
python examples/secure_request_example.py plan
python examples/secure_request_example.py assemble
```

#### 签名算法

1. 取 `operation`、`payload`、`key_id`、`timestamp`、`nonce` 五个字段
   （**不含** `signature`）组成签名对象；
2. 固定 JSON 规范化（**签名双方必须完全一致**）：
   - 键按字典序递归排序；
   - 无任何多余空白（分隔符为 `,` 与 `:`）；
   - UTF-8 编码、非 ASCII 字符不转义（`ensure_ascii=false`）；
   - 不允许 `NaN` / `Infinity`；
3. 用 `SECURE_REQUEST_KEYS` 中 `key_id` 对应的密钥，对规范化字节串计算
   HMAC-SHA256，输出小写十六进制作为 `signature`。

Python 参考实现（标准库）：

```python
import hashlib, hmac, json, time, uuid

def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")

envelope = {
    "operation": "plan",
    "payload": payload,
    "key_id": "demo-key",
    "timestamp": int(time.time()),
    "nonce": uuid.uuid4().hex,
}
envelope["signature"] = hmac.new(
    b"0123456789abcdef0123456789abcdef",
    canonical_json(envelope),
    hashlib.sha256,
).hexdigest()
```

#### 服务端校验顺序

1. 服务端未配置任何密钥 → `503 keys_not_configured`；
2. `|server_time - timestamp|` 超过 `SECURE_REQUEST_TIMESTAMP_SKEW`
   → `401 timestamp_skew`（响应附带 `server_time` 与 `max_skew_seconds`）；
3. `key_id` 在密钥表中不存在 → `401 unknown_key_id`；
4. 重算签名并常量时间比较，不一致 → `401 invalid_signature`；
5. 同一 `key_id+nonce` 仍在 `SECURE_REQUEST_NONCE_TTL` 窗口内
   → `409 nonce_replayed`；
6. 校验 `payload` 并执行对应操作：字段错误返回 `422 invalid_request`
   （错误路径以 `payload.` 开头，如 `payload.ranges[0].end`），
   业务语义错误沿用 `/plan`、`/assemble` 的 `422` 错误结构。

只有**执行成功（HTTP 200）**的请求才会占用 nonce；验签通过但 payload
非法或业务校验失败的请求会回滚 nonce 占位，客户端修正后可用同一 nonce
重试。重放已成功的 nonce 返回 `409`。

## 错误响应

业务请求/语义错误统一返回 HTTP `422`：

- 字段类型或约束错误：`{"error": "invalid_request", "detail": [...]}`；
  `/secure-request` 中 payload 字段错误的路径以 `payload` 开头；
- `/plan` 范围不可满足：`{"error": "unsatisfiable", "message": ..., "range_index": ...}`；
- `/assemble` 组装错误：`{"error": "<code>", "detail": [{"message": ..., "loc": ...}]}`，
  其中 `loc` 指向出错的字段路径（如 `contents[2].data_b64`、
  `mappings[0].slices[1]`），并按需附带 `block_index` / `cache_id` /
  `range_index` / `slice_index`。主要错误码：

  | error                       | 含义                               |
  | --------------------------- | ---------------------------------- |
  | `missing_block`             | 缺少回源块内容                     |
  | `duplicate_block_content`   | 同一回源块内容被重复提供           |
  | `unexpected_block`          | 提供了 blocks 中不存在的回源块     |
  | `duplicate_block`           | blocks 中块编号重复                |
  | `missing_cache`             | 缺少缓存块内容                     |
  | `duplicate_cache_content`   | 同一缓存块内容被重复提供           |
  | `unexpected_cache`          | 提供了 cached_blocks 中未声明的 id |
  | `duplicate_cache`           | cached_blocks 中缓存 id 重复       |
  | `invalid_cache`             | 缓存块区间非法                     |
  | `cache_out_of_bounds`       | 缓存块超出对象长度                 |
  | `cache_length_mismatch`     | 缓存内容解码字节数与声明长度不符   |
  | `unknown_cache_reference`   | 切片引用了未声明的缓存块           |
  | `invalid_base64`            | Base64 非法或填充错误              |
  | `block_length_mismatch`     | 解码字节数与声明长度不符           |
  | `invalid_slice`             | 切片来源字段组合非法或偏移非法     |
  | `slice_out_of_bounds`       | 切片超出来源块边界                 |
  | `assembly_length_mismatch`  | 切片总长与范围声明长度不符         |
  | `slice_misaligned`          | 切片不能连续覆盖该范围             |
  | `unknown_block_reference`   | 切片引用了不存在的回源块           |
  | `slice_block_mismatch`      | 切片记录的区间与来源块声明不一致   |
  | `block_out_of_bounds`       | 回源块超出对象长度                 |
  | `duplicate_mapping_index`   | mappings 中下标重复                |
  | `invalid_mapping_index`     | mappings 下标未覆盖 0..N-1         |

`/secure-request` 的鉴权类错误（均为 `{"error": ..., "message": ...}`）：

| HTTP | error                 | 含义                                              |
| ---- | --------------------- | ------------------------------------------------- |
| 401  | `timestamp_skew`      | 时间戳超出允许偏差（附 `server_time`、`max_skew_seconds`） |
| 401  | `unknown_key_id`      | 密钥表中不存在该 `key_id`（附 `key_id`）          |
| 401  | `invalid_signature`   | HMAC-SHA256 签名不符                              |
| 409  | `nonce_replayed`      | 同一 `key_id+nonce` 在有效窗口内已成功使用（附 `key_id`） |
| 503  | `keys_not_configured` | 服务端未配置 `SECURE_REQUEST_KEYS`，鉴权入口不可用 |

`/secure-request` 信封本身字段缺失或类型错误（如缺少 `signature`、
`timestamp` 不是整数）同样返回 `422 invalid_request`。

## 本地开发（不使用 Docker）

```
pip install -r requirements.txt
export SECURE_REQUEST_KEYS='demo-key=0123456789abcdef0123456789abcdef'
uvicorn app.main:app --reload --port 8080
```
