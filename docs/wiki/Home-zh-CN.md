# 中文首页

欢迎。本 Wiki 是 TypeBit 下载引擎核心的操作手册。README 讲它是**什么**，
这里讲怎么**驱动它**。

## 页面

- **[快速开始](Getting-Started-zh-CN)** — 引入 crate、解析链接、跑完整引擎
  生命周期（真实可编译代码）
- **[Engine API](Engine-API-zh-CN)** — 每个 `Engine` 方法和 `EngineEvent`，
  一张表讲完
- **[实现 Host](Implementing-a-Host-zh-CN)** — 你唯一需要写的那层接口
- **[支持的格式](Supported-Formats)** — 每种链接格式及其限制（中英双语）
- **[架构](Architecture-zh-CN)** — 模块地图、分层、tick 流水线
- **[FFI 绑定](FFI-Binding-zh-CN)** — 对接 Kotlin / Swift / C# / Go 的 C ABI
- **[发布](Publishing-zh-CN)** — 发布到 crates.io
- **[Home (English)](Home)** — English entry

## 三十秒带你了解 TypeBit 模型

```
你的应用（UI / Kotlin / Swift …）
        │ 调用
        ▼
┌─────────────────────────────────────────────┐
│  typebit::Engine  （会话 + DHT + 缓存）       │
│  └─ typebit::session::TorrentSession         │
│  └─ typebit::dht::Dht                        │
│  └─ typebit::disk_cache::DiskCache           │
└─────────────────────────────────────────────┘
        │ 每个 tick 调用（在你的线程上）
        ▼
typebit::Host  ◄── 你来实现这一层
   （socket、文件、时钟、随机数）
```

引擎从不碰操作系统。它向 `Host` 要一切：连 socket、读文件、给时间、填熵。
你的活就是写一个无聊但可靠的 `Host` 实现。所有聪明的东西（选片、DHT、
receipt、磁盘缓存）都在引擎里。

跑 `cargo run --example minimal_host` 看一个完整可运行的 `Host`
实现（内存版）驱动真实引擎。

## 许可提醒

TypeBit 采用 PolyForm Perimeter License 1.0.0
（<https://polyformproject.org/licenses/perimeter/1.0.0>）。许可证全文
（含其 noncompete 条款）见 LICENSE。
