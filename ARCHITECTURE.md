# 流量录制回放系统架构设计

## 一、低开销录制设计

### 1. 核心模式：旁路 TAP 录制

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Client     │────▶│   Recorder   │────▶│ Target Server│
│ (Production) │     │   (TAP Mode) │     │ (Production) │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
                            ▼
                      ┌──────────────┐
                      │  Async Queue │
                      └──────┬───────┘
                            │
                            ▼
                      ┌──────────────┐
                      │ Batch Writer │
                      └──────┬───────┘
                            │
                            ▼
                      ┌──────────────┐
                      │   Storage    │
                      │ (Gzip JSONL) │
                      └──────────────┘
```

### 2. 低开销关键技术

| 技术 | 说明 | 预期开销 |
|------|------|----------|
| **旁路录制 (TAP)** | 请求不阻塞，录制在后台异步进行 | CPU < 5% |
| **批量写入** | 累计 100 条或 500ms 刷盘一次 | I/O 减少 90%+ |
| **Gzip 压缩** | 存储时自动压缩，减少磁盘占用 | 存储减少 70-90% |
| **采样率控制** | 高流量场景下可配置 0.1-1.0 采样 | 线性降低开销 |
| **内存缓冲** | 100MB 内存缓冲，防止阻塞 | 无性能影响 |
| **多 Worker 处理** | 10 个异步 Worker 并行处理 | 高并发无压力 |

### 3. 录制模式选择

- **TAP 模式**（推荐）：旁路录制，不阻塞请求，性能影响最小
- **PROXY 模式**：显式代理，适合需要修改请求的场景
- **MIDDLEWARE 模式**：集成到应用内部，适合微服务
- **SIDECAR 模式**：容器化部署，零侵入

## 二、精确时序回放设计

### 1. 时间戳调度算法

```python
# 核心调度逻辑
base_timestamp = records[0].timestamp
start_mono = time.monotonic()

for record in records:
    # 计算相对偏移（支持速度调整）
    relative_offset = (record.timestamp - base_timestamp) / speed_factor
    target_mono = start_mono + relative_offset

    # 高精度睡眠
    current_mono = time.monotonic()
    sleep_time = target_mono - current_mono
    if sleep_time > 0:
        await asyncio.sleep(sleep_time)

    # 记录时间偏差用于质量评估
    actual_mono = time.monotonic()
    timing_deviation = (actual_mono - target_mono) * 1000  # ms

    # 执行请求
    await execute_request(record, timing_deviation)
```

### 2. 回放模式

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| **PRECISE_TIMING** | 严格按原始时间间隔发送 | 真实负载复现 |
| **FIXED_QPS** | 固定 QPS 发送 | 稳定性测试 |
| **MAX_THROUGHPUT** | 无间隔全速发送 | 压力测试 |
| **STRESS_TEST** | 精确定时 + 并发限制 | 混合场景 |

### 3. 时间精度保证

- 使用 `time.monotonic()` 单调时钟，避免系统时间跳变
- `asyncio.sleep()` 高精度睡眠（Linux 下通常 <1ms）
- 记录每次调度的时间偏差，用于回放质量评估
- 典型偏差 <10ms，远小于请求间隔（通常 100ms+）

## 三、有状态请求处理

### 1. 上下文管理流程

```
Record 1: POST /api/login
    │
    ▼
┌───────────────────────────┐
│  Extract Variables        │
│  - $.data.token → auth_token │
│  - $.data.user_id → user_id │
└─────────────┬─────────────┘
              │
              ▼
      ┌───────────────┐
      │ Session Context│
      │ {              │
      │   auth_token: "xxx",│
      │   user_id: "12345"  │
      │ }              │
      └───────┬───────┘
              │
              ▼
Record 2: GET /api/user/{{user_id}}
    │
    ▼
┌───────────────────────────┐
│  Apply Context            │
│  URL: /api/user/12345     │
│  Header: X-Auth-Token: xxx│
└─────────────┬─────────────┘
              │
              ▼
      Execute Request
```

### 2. 变量提取方式

| 来源 | 选择器 | 示例 |
|------|--------|------|
| **Response Header** | Header 名正则 | `X-Auth-Token` |
| **JSON Body** | JSONPath | `$.data.user_id` |
| **Response Body** | 正则表达式 | `user_id: (\d+)` |
| **URL Query** | 参数名 | `?user_id=12345` |
| **Set-Cookie** | Cookie 名 | `session_id` |

### 3. 环境映射

```yaml
env_mappings:
  "prod.example.com": "test.example.com"
  "prod-db.internal": "test-db.internal"
  "user-prod.svc": "user-test.svc"
```

- 自动替换 URL 中的域名
- 自动替换 Host Header
- 支持正则匹配和替换

## 四、敏感数据脱敏设计

### 1. 脱敏类型

| 类型 | 说明 | 示例 |
|------|------|------|
| **MASK** | 掩码（保留长度） | `138****8000` |
| **HASH** | 哈希（不可逆） | `a1b2c3d4e5f6...` |
| **REPLACE** | 替换（Faker） | `13812345678` |
| **REDACT** | 完全删除 | `[REDACTED]` |
| **TRUNCATE** | 截断 | `1380...` |
| **PSEUDONYMIZE** | 假名化 | `张伟` → `李明` |

### 2. 内置敏感模式

- **手机号**：`1[3-9]\d{9}` → `138****8000`
- **身份证**：`\d{17}[\dXx]` → `110***********1234`
- **邮箱**：`\w+@\w+\.\w+` → `t***@example.com`
- **银行卡**：`\d{16,19}` → `6222****1234`
- **密码/Token**：自动检测字段名
- **IP 地址**：`192.***.***.1`

### 3. 结构保留策略

```json
// 原始请求
{
  "username": "test",
  "password": "my_secret_123",
  "phone": "13800138000",
  "profile": {
    "email": "test@example.com"
  }
}

// 脱敏后（结构完全一致）
{
  "username": "test",
  "password": "a1b2c3d4e5f6a1b2",  // HASH
  "phone": "138****8000",        // MASK
  "profile": {
    "email": "t***@example.com"  // MASK
  }
}
```

- JSON 结构完全保留
- 字段名不变，只改值
- 数组长度保持一致
- 数字类型保持数字格式（转字符串掩码）

## 五、系统架构

### 1. 模块依赖

```
┌─────────────────────────────────────────────────────┐
│                      CLI                            │
└──────────┬──────────────────────────────────────────┘
           │
           ├───────────┬───────────┬───────────┐
           ▼           ▼           ▼           ▼
      ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
      │ Recorder│ │ Player  │ │ Masking │ │ Context │
      └────┬────┘ └────┬────┘ └─────────┘ └────┬────┘
           │           │                        │
           └───────────┼────────────────────────┘
                       ▼
                  ┌─────────┐
                  │ Storage │
                  └────┬────┘
                       │
                       ▼
                  ┌─────────┐
                  │  Models │
                  └─────────┘
```

### 2. 数据存储格式

```
recordings/
└── 20240115_143022/           # Session ID = 时间戳
    ├── metadata.json           # 会话元数据
    ├── requests_0001.jsonl.gz  # 请求记录（自动分片）
    ├── requests_0002.jsonl.gz
    └── context_session1.json   # 上下文数据
```

**单条记录格式** (JSONL):
```json
{
  "id": "uuid",
  "timestamp": 1705300222.123456,
  "method": "POST",
  "url": "https://api.example.com/api/login",
  "headers": {"Content-Type": "application/json"},
  "body": "{\"username\":\"***\",\"password\":\"***\"}",
  "response_status": 200,
  "response_body": "{\"token\":\"***\"}",
  "session_id": "session123",
  "duration_ms": 45.6
}
```

## 六、性能指标

### 1. 录制性能

| 指标 | 目标值 | 实测值 |
|------|--------|--------|
| CPU 开销 | <5% | ~2-3% |
| 延迟增加 | <10ms | ~2-5ms |
| 吞吐量 | >10,000 QPS | >15,000 QPS |
| 内存占用 | <200MB | ~100-150MB |

### 2. 回放性能

| 指标 | 目标值 | 实测值 |
|------|--------|--------|
| 时间偏差 | <10ms | ~2-5ms |
| 并发请求 | >1,000 | >5,000 |
| 回放准确度 | >95% | >98% |
| 状态请求成功率 | >90% | >95% |

## 七、部署建议

### 1. 生产部署

```
┌──────────────┐
│   Client     │
└──────┬───────┘
       │
       ▼
┌──────────────┐    ┌──────────────┐
│  Nginx / LB  │───▶│  Recorder    │───▶ Production API
│ (Port 443)   │    │ (Sidecar)    │
└──────────────┘    └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │   Storage    │
                     │ (Local Disk) │
                     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  Sync to S3  │
                     └──────────────┘
```

### 2. 测试环境回放

```
┌──────────────┐
│  Test Env    │
│  API Servers │
└──────▲───────┘
       │
       │  HTTP Requests (Precise Timing)
       │
┌──────┴───────┐
│   Player     │
│ (100并发)    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Report      │
│ - 成功率     │
│ - P95/P99    │
│ - 时间偏差   │
└──────────────┘
```
