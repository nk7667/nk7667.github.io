---
layout: single
title: "VulnScope：基于流水线的 DAST 黑盒扫描平台"
date: 2026-07-09
categories:
  - github项目
  - DAST
---

## VulnScope：基于流水线的 DAST 黑盒扫描平台

[VulnScope](https://github.com/nk7667/VulnScope) 是一个 Go + Vue + Redis + MySQL 的黑盒漏洞扫描平台，后端通过 Asynq 将扫描动作拆成多阶段任务，由 Worker 异步消费，扫描引擎调用 nmap 和 nuclei。

### 架构

```text
用户 → API Server → Scheduler → Redis 队列 → Worker → 扫描器(nmap/nuclei)
                                                   ↓
                                             结果写入 MySQL
```

三种运行模式（[main.go](https://github.com/nk7667/VulnScope/blob/main/cmd/scanner/main.go)）：

| 模式 | 启动参数 | 包含组件 |
|------|---------|---------|
| all | `-mode=all` | API + Worker |
| server | `-mode=server` | 仅 API |
| worker | `-mode=worker` | 仅 Worker |

API 和 Worker 共享 Redis 和 MySQL，Worker 节点可独立扩容。

### 扫描流水线

一次扫描拆为五段，按顺序执行：

```text
domain（域名解析）→ alive（存活探测）→ port（端口扫描）→ finger（指纹识别）→ vuln（漏洞扫描）
```

任务类型常量（[scheduler.go](https://github.com/nk7667/VulnScope/blob/main/internal/scheduler/scheduler.go#L19-L26)）：

```go
const (
    TypeDomainScan = "scan:domain"
    TypeAliveScan  = "scan:alive"
    TypePortScan   = "scan:port"
    TypeFingerScan = "scan:finger"
    TypeVulnScan   = "scan:vuln"
)
```

每段完成后，Worker 通过回调 `EnqueueFunc`（[worker.go](https://github.com/nk7667/VulnScope/blob/main/internal/worker/worker.go#L26)）通知 Scheduler 将下一阶段任务入队。

### 任务调度

Scheduler 是入队的唯一入口（[scheduler.go](https://github.com/nk7667/VulnScope/blob/main/internal/scheduler/scheduler.go#L38-L44)），持有 `asynq.Client`（入队）、`asynq.Inspector`（查询队列和取消任务）和 `redis.Client`（标记取消）。

`EnqueueTask`（[scheduler.go](https://github.com/nk7667/VulnScope/blob/main/internal/scheduler/scheduler.go#L68-L123)）从数据库获取任务和目标准备入队。任务载荷为 `ScanPayload`（[scheduler.go](https://github.com/nk7667/VulnScope/blob/main/internal/scheduler/scheduler.go#L29-L35)）：

```go
type ScanPayload struct {
    TaskID         uint     `json:"task_id"`
    Targets        []string `json:"targets"`
    TemplateIDs    []string `json:"template_ids,omitempty"`
    IsRetest       bool     `json:"is_retest,omitempty"`
    OriginalTaskID uint     `json:"original_task_id,omitempty"`
}
```

#### 阶段推进：按单目标粒度入队

`EnqueueNextStage`（[scheduler.go](https://github.com/nk7667/VulnScope/blob/main/internal/scheduler/scheduler.go#L208-L259)）不是将整批目标打包成一个任务，而是为每个目标单独创建一条队列任务：

```go
for _, target := range targets {
    payload := ScanPayload{
        TaskID:  taskID,
        Targets: []string{target},
    }
    if err := s.enqueue(nextType, payload, 3); err != nil { continue }
}
```

`vuln` 阶段完成后直接标记任务结束：

```go
case "vuln":
    task.Status = "completed"
    task.Progress = "done"
    return s.store.UpdateTask(task)
```

#### 队列过载保护

入队前检查目标队列 pending 数，超过 10000 时用 `asynq.ProcessIn` 延迟 5 分钟入队：

```go
const taskOverloadLimit = 10000
queueInfo, _ := s.inspector.GetQueueInfo(queueName)
if queueInfo.Pending > taskOverloadLimit {
    task := asynq.NewTask(taskType, data,
        asynq.Queue(queueName),
        asynq.ProcessIn(5 * time.Minute))
    s.client.Enqueue(task)
}
```

### 任务消费

Worker 在初始化时配置四级队列权重（[worker.go](https://github.com/nk7667/VulnScope/blob/main/internal/worker/worker.go#L49-L58)）：

```go
Queues: map[string]int{
    "retest":  9,
    "high":    6,
    "default": 3,
    "low":     1,
}
```

五种扫描类型各注册一个处理器，每个 `handleXXX` 都通过 `cancelHandler` 包装（[worker.go](https://github.com/nk7667/VulnScope/blob/main/internal/worker/worker.go#L155-L168)）：实际工作在 goroutine 中执行，主线程监听 `ctx.Done()`，超时或取消时返回 `asynq.SkipRetry`。

#### 以端口扫描为例

`doPortScan`（[worker.go](https://github.com/nk7667/VulnScope/blob/main/internal/worker/worker.go#L404-L525)）流程：

1. `isTaskCancelled` 检查取消状态（优先查 Redis Set，回退数据库）
2. `isStageCompleted` 幂等检查
3. 分离"已带端口的目标"和"需要扫描的目标"
4. 对后者调用 `scanner.PortScan`（底层 nmap）
5. 将开放端口展开为 `host:port` 格式，截断上限 30 个端口
6. 结果入队下一阶段：`w.enqueue("port", p.TaskID, nextTargets)`

每个目标完成后立即触发下一阶段。例如 `host:80` 和 `host:443` 会作为两个独立任务进入 `finger` 队列，由不同 Worker 并行消费。

#### 漏洞扫描

`doVulnScan`（[worker.go](https://github.com/nk7667/VulnScope/blob/main/internal/worker/worker.go#L652-L781)）需要先做模板匹配：

1. 从端口扫描结果获取 CPE 和 Service
2. 端口推断（如 3306 → mysql）和 HTTP 探测
3. `GetMatchedVulnTemplates` 按 CPE/Service 筛选适用模板
4. `VulnScanByService` 按 HTTP/TCP 分组调用 nuclei，结果写入 `CreateVuln`
5. 扫描完成后 `DisableHighFalsePositiveTemplates` 自动禁用误报率 ≥ 80% 的模板

#### 限速与过滤

- **目标级 QPS 限速**（[worker.go](https://github.com/nk7667/VulnScope/blob/main/internal/worker/worker.go#L120-L148)）：按 host 维度 `rate.Limiter`，默认 10 QPS
- **目标排除**：支持精确匹配、CIDR、子域名通配符
- **端口排除**：按端口号黑名单过滤
- **IP 冷却**：通过 Config 表记录上次扫描时间，冷却期内跳过

### 任务生命周期

**取消**（[scheduler.go](https://github.com/nk7667/VulnScope/blob/main/internal/scheduler/scheduler.go#L268-L322)）：遍历四个队列，`ListPendingTasks` 删除待执行任务，`ListActiveTasks` 取消执行中任务，同步标记 Redis Set 让 Worker 毫秒级感知。

**暂停/恢复**：直接修改数据库任务状态。

### 扫描器层

五个阶段对应的扫描器（[internal/worker/scanner/](https://github.com/nk7667/VulnScope/tree/main/internal/worker/scanner)）：

| 文件 | 阶段 | 底层工具 |
|------|------|---------|
| domain.go | 域名解析 | net.LookupHost |
| alive.go | 存活探测 | HTTP/TCP 连接探测 |
| port.go | 端口扫描 | nmap |
| finger.go | 指纹识别 | nuclei |
| vuln.go | 漏洞扫描 | nuclei |

漏洞扫描支持按服务协议分组（`VulnScanByService`），HTTP 服务用 HTTP 模板，TCP 服务用 TCP 模板。

### 数据模型

核心模型（[model.go](https://github.com/nk7667/VulnScope/blob/main/internal/model/model.go)）：

| 模型 | 说明 |
|------|------|
| Target | 扫描目标（ip / domain / cidr） |
| Task | 扫描任务（status / progress / type） |
| Asset | 扫描发现的资产（IP / Domain / Title / StatusCode） |
| Port | 资产端口（Port / Protocol / Service / CPE / Banner） |
| Finger | 资产指纹（Name / Category / Version） |
| Vuln | 漏洞结果（Name / Severity / URL / TemplateID / Status） |
| Template | nuclei 模板（Name / Category / Tags / Severity / YAML） |
| TaskLog | 任务日志（Stage / Level / Message） |

### 项目结构

```
VulnScope/
├── cmd/scanner/              # 程序入口
├── internal/
│   ├── config/               # 配置加载
│   ├── model/                # 数据模型（GORM）
│   ├── store/                # 数据库操作 + 模板匹配
│   ├── scheduler/            # 任务调度（入队、取消、暂停）
│   ├── worker/               # 任务执行 + 扫描器封装
│   │   └── scanner/          # nmap/nuclei 子进程调用
│   ├── server/               # HTTP API（Gin）
│   │   └── handler/          # 请求处理
│   └── checker/              # 环境检查
├── web/                      # Vue 3 + Element Plus 前端
├── schema.sql                # MySQL 建表语句
└── config.yaml               # 配置文件
```