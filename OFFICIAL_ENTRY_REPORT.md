# CI-TRACE：绑定业务授权与 Git 发布对象的可核验安全交付

## 摘要

代码审核通过并不代表某个制品获准交付给特定接收方。CI-TRACE 将来源、制品摘要、接收方、目标 Git 引用、原基线和操作编号绑定到短时授权，用一次性预留与原子引用创建执行发布，依据远端 Git 对象恢复模糊结果，并提供离线历史验签。作品包括可运行的本地国密/mTLS/Git 实验、真实 Gitee 测试仓库 Web 合并证据和 GitHub 托管只读见证。九种本地场景与全新目录复现均通过。实验密钥仍由研究主体管理，Gitee 仅验证 Web 路径；不宣称厂商签章、生产双人审批或 Git CLI 授权闭环。

关键词：持续集成；发布授权；SM2/SM3；Git 原子引用；离线验签。

## 第一章 作品概述

### 1.1 背景与问题

普通开发者可以参与代码审查和修改流水线，但“制品能否交付给接收方 B”需要独立的业务判断。发行者可能替换已批准的摘要、接收方或目标引用；并发进程可能在检查后抢先创建目标分支；Git 推送成功而 ACK 丢失时，盲目重试也会制造歧义。仅对一份自述的 JSON 验签，不能自动核实其 Git 对象关系。

### 1.2 相关工作和研究范围

GitHub 已支持自定义部署保护规则与制品证明；Azure Pipelines 提供审批、外部检查与独占锁；SLSA Source v1.2 要求审批适用于最终修订和特定上下文。因此，外部审批或签名并非本作品首创。本研究面向专用交付引用、客户接收方和审计需求，解决业务授权与实际 Git 发布对象之间的绑定和故障恢复问题。

### 1.3 威胁模型

普通研发身份不应拥有受保护目标引用的直接写入权；授权密钥、可信公钥指纹、目标 Git 写入身份应独立于普通研发权限。实验账号及 LAB 密钥仍由同一研究主体控制，尚不能证明组织级职责分离。安全目标是拒绝错接收方、错摘要、过期和撤销授权；一次操作仅允许一个发行者占用；只在目标 ref 为空时创建；发布确认必须绑定实际远端对象。它不承诺目标业务系统恰好一次成功处理，也未解决同 UID 私钥窃取。

## 第二章 作品设计与实现

### 2.1 授权主体与通信

发布主体记录来源平台/工作流、源 SHA、制品摘要、业务接收方、仓库、目标 ref、目标原基线和操作编号。R23 国内适配实验使用 OpenSSL SM2/SM3 签署短时 grant；实验 CA 支持 issuer 与 publisher 之间的 mTLS，SQLite 串行化一次性预留。CodeArts 和 Gitee Go 入口是研究者定义的事件契约，不是厂商原生云任务。

### 2.2 原子 Git 发布与恢复

发行者校验授权字段、制品字节和有效期，将制品写入一次性本地 bare Git 实验仓库的提交，以 create-only lease 创建目标引用。随后读取远端 ref、commit、tree、制品对象并形成回执。ACK 丢失时只读核验远端对象，不能以账本 RESERVED 状态推断成功。R22 主协议采用 Ed25519 实验密钥，R23 国密适配是另一条本地链路；二者不能合称为 Gitee SaaS 上已落地的单次 SM2 Git CLI 发布。

### 2.3 分层证据与运行入口

本地控制实验、Gitee 真实 Web 权限和合并历史、R27 离线原始对象交叉核验、R28 GitHub 托管见证分别标记。评委可在解压后运行 `python3 ci_trace.py demo --output run_output`；主命令无需联网、账号或平台令牌，结果存为 `run_output/summary.json`。另可运行 `python3 ci_trace.py verify-gitee` 仅验证历史归档。

## 第三章 作品测试与分析

### 3.1 环境、方法与回归

使用 Python 3.11+、Git、支持 SM2/SM3 的 OpenSSL 3.x 和 `cryptography`。可执行 ZIP 解压到新目录后，单命令在本次沙箱约 5 秒完成。本地 R23 三组 unittest 共 48 项通过，R22 协议回归 30 项通过。旧 Web UI 的 FastAPI/pytest 产品测试因本环境缺少依赖未计入本次验收。所有场景均在一次性本地 Git 仓库运行，不写 Gitee。

### 3.2 安全机制与性能

九种作者设计场景均通过：合法发布、错误接收方、制品替换、过期、撤销、重放、64 路并发争用、ACK 丢失恢复及目标 ref 抢占。同场景作者自建 A 代理出现 5 个未授权副作用案例，较强 B 代理出现 1 个，CI-TRACE 研究协议出现 0 个。B 已包含业务字段、摘要、时效、撤销和一次性账本；差异在普通 Git 推送的检查后竞争和缺少远端对象级恢复。这是机制消融，不是商用平台安全排名或真实误报率。

每场景 10 次同机时延测量中，合法发布 p50 为 147.26 ms、p95 为 167.93 ms；ACK 丢失恢复 p50 为 225.29 ms、p95 为 401.13 ms。这是共享沙箱中 bare Git/SQLite/Python 的实验数据，不代表 Gitee 网络和生产时延。

### 3.3 平台实证与离线核验

Gitee 测试仓库 `liljunlin/test` 的专用分支 `ci-trace-r26-protected-20261017` 开启保护，研发账号 Web 直写遭拒，owner 审查并合并公开 PR !1；合并提交是 `12401c28e176fbb0cd3ff920f5bc5936d98ba6fd`。这不是 Git CLI receive-pack 拒绝实验。

R27 归档 SHA-256 为 `0426dd4dca6e0222d5c168ab08a5efdddca91e60265ed4fb6544a4120f4307db`，LAB 公钥指纹为 `8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d`。离线原包通过，对临时副本的原始对象改动被拒。归档 Gitee API 快照没有厂商数字签章。

GitHub 托管 run 39031776743 的两个作业分别做公开状态回读和见证复核，签名见证 56943794 的主体被修改后拒绝。它证明特定工作流签过见证字节，不是独立业务审批。R28 另抽取 24 个公开 PR，13 个可见合并前批准，3 个审批锚不同于最终 head；仅 1 个确认最终链上后续提交。此样本不构成平台漏洞率或本作品的误报率。

## 第四章 创新性说明

一是将授权绑定到一次确切的业务交付操作，而不只依据“代码已审核”。二是把强业务检查接到 Git 原子 create-only 引用更新，展示检查后普通推送的竞争窗口。三是用实际远端 Git 对象解决模糊 ACK，再以独立固定的公钥和归档原始对象离线核验历史回执。四是明确分层本地故障注入、真实平台 Web 行为与托管签名观察，防止实验结论越界。组合价值尚需与现有商用系统在统一威胁模型下公平比较，不主张首创外部审批、密码签名或 SLSA 源证明。

## 第五章 总结

作品已形成可独立运行的研究版交付包，包含源码、单命令演示、测试结果、真实平台证据索引和离线核验归档。主要限制是 Gitee Git CLI 直推拒绝与发布身份权限未实测；两个账号和 LAB 私钥由同一研究者控制；真实 CodeArts/Gitee Go 流水线、跨机器 mTLS、生产审批、独立盲标业务样本和长期运维尚未完成。R25 自建 Git hook 不能假设安装在 Gitee SaaS。托管 artifact 默认七天留存，长期证明应归档见证主体和 bundle。当前不主张生产可用、商用密码合规认证或 SLSA Source Level 3。

## 参考文献

[1] GitHub Docs. Creating custom deployment protection rules. https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/create-custom-protection-rules

[2] GitHub Docs. Artifact attestations. https://docs.github.com/en/actions/concepts/security/artifact-attestations

[3] Microsoft Learn. Pipeline deployment approvals. https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals

[4] SLSA. Source: Requirements for producing source, v1.2. https://slsa.dev/spec/v1.2/source-requirements

[5] Gitee 测试仓库 PR !1. https://gitee.com/liljunlin/test/pulls/1

[6] CI-TRACE 托管 run 39031776743. https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031776743
