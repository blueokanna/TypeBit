# 发布到 crates.io

TypeBit 以**单一 crate**（`typebit`）发布。CI 在合并前验证的就是即将发布的
那个产物；打 tag 触发发布工作流。

## 一次性前置

1. 在 crates.io 创建 API token：<https://crates.io/settings/tokens>
   （权限 `publish-new` / `publish-update`）。
2. 把它加为仓库 secret **`CARGO_REGISTRY_TOKEN`**：
   Settings → Secrets and variables → Actions → New repository secret。

## 发布流程

```sh
# 1. 在 Cargo.toml 里升级版本（changelog 要如实写）。
# 2. 提交并推到 main（CI 跑完整矩阵）。
# 3. 打 'v' 前缀的 tag 并推送：
git tag v0.1.7
git push origin v0.1.7
```

`publish` 工作流（`.github/workflows/publish.yml`）随后：

1. 检出该 tag，
2. 跑 `cargo package`（与最终发布完全相同的产物），
3. 用 token 执行 `cargo publish`。

## 打 tag 前 CI 已经强制什么

- `cargo fmt --check`
- `clippy -D warnings`：`no-default-features`、`std`、`std,ffi`、
  `--all-features`——Linux、Windows **和** macOS 三平台
- `cargo test --all-features` 与 `cargo test --no-default-features`
  （真的执行 `no_std` 代码路径，不只是编译检查）
- `cargo doc --all-features`（rustdoc 必须能构建）+ doc tests
- 裸机 `no_std` 目标：`aarch64-unknown-none`、`thumbv7em-none-eabihf`、
  `riscv32imac-unknown-none-elf`
- MSRV 1.95（用 Rust 1.95 跑 `cargo check`）
- 对照 `Cargo.lock` 的 `cargo-audit`
- `cargo package` + `cargo package --list`

## 包内容

`Cargo.toml` 的 `include` 会带上 `src/**`、`README.md`、`LICENSE`、
`docs/**`（wiki 就在仓库内、随 crate 一起发布）和 `examples/**`。

```sh
cargo package --list   # 查看压缩包内容
cargo package          # 构建并验证最终产物
```

## docs.rs

`Cargo.toml` 里的 `[package.metadata.docs.rs]` 会用 `--all-features` 和
`--cfg docsrs` 构建文档，因此 FFI 符号、`StdHost` 和 feature 门控模块都能
正确渲染（带 `doc(cfg)` 徽章）。每个公开项都有 `///` 文档
（`#![warn(missing_docs)]`）；CI 的 `doc` job 会在任何 intra-doc 链接失效时
让构建失败。

## 版本策略

Semver。1.0 之前：`0.x.y`——破坏性变更升 `x`，功能/修复升 `y`。FFI 在
1.0 之前**明确不稳定**（文档已注明）。
