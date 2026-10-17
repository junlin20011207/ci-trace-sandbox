# CI-TRACE：绑定业务授权与 Git 发布对象的可核验安全交付

## 作品简介

CI-TRACE 面向持续集成流水线中“代码可合并，但某个制品能否向某个接收方发布”这一不同的授权问题。研究版把制品摘要、来源、接收方、操作编号、Git 目标引用和原基线编入一次性批准；使用原子创建目标引用限制并发覆盖；在发布后回读真实 Git 对象，遇到 ACK 丢失时只依据远端状态恢复。实验回执提供离线验证入口。本作品是防御性研究原型。

**评委可执行的最短路径：** Python 3.11+、Git、OpenSSL 3.x、`cryptography`，在包根目录运行 `python3 ci_trace.py demo --output run_output`；检查控制台 JSON 和 `run_output/summary.json`。无需联网、账号或凭据。演示约数秒，具体耗时取决于机器。

## 1. 问题、威胁模型和安全目标

普通开发者能够修改流水线代码或尝试直接写 Git，不能因此被视为某个接收方发布的业务批准者。发行者可能错误替换制品、接收方或目标引用；并发发行者可能争用一次授权；Git push 已成功但 ACK 丢失会诱使盲目重试；审计者可能只拿到一个“签名为真”但内部 Git 对象关系错误的 JSON。

受信假设：授权签名密钥、可信公钥指纹、受保护 Git 目标的写入权限和 GitHub 托管运行身份独立于普通研发权限。在本作品实验中，前两项仍由同一研究主体管理，不能据此宣称组织级职责分离。R25 自建 server hook 只在自建 Git 服务器存在，Gitee SaaS 的受保护分支须依赖平台现有规则。

安全目标：拒绝错接收方、错摘要、过期与撤销的授权；同一操作只允许一个发行者占用；目标 ref 只能在确认为空时创建；发布确认必须绑定实际远端对象；历史证据可由已事先固定的公钥和对象字节离线重算。它不保证目标系统“恰好一次收到业务效果”、抵抗同 UID 窃取私钥、厂商 API 签章或生产跨组织部署。

## 2. 系统设计与交付协议

申请者提交的发布主体包含来源平台/工作流、源 SHA、制品 SHA-256 或 SM3、业务接收方、仓库、目标 ref、目标原基线和操作 ID。授权方按策略检查后以 SM2 签署短时 grant；发行方经 mTLS 调用单次预留，验证所有绑定字段，把制品写入一次性本地 Git 提交，以 create-only lease 推送。成功后读取远端 ref/commit/tree/制品并签回执；模糊 ACK 时只读重查 Git 对象，状态不明则保持 HOLD。

R22 主协议用 Ed25519 研究密钥，R23 国内适配实验用 OpenSSL SM2/SM3；两条本地实验共享目标，但不是已经合并成 Gitee SaaS 的单个云端产品。R26–R28 是另一次 Gitee Web PR 的历史平台证据及其离线/托管复核，不应串称“SM2 直接放行了 Gitee Git CLI push”。

## 3. 可复现证据与结果

| 证据层 | 输入、结果 | 允许的结论 |
| --- | --- | --- |
| 本地隔离控制 | R23 三组 unittest 共 48 项通过；R22 协议 30 项通过；整合入口 9/9 场景通过，两种研究契约各完成一次 SM2 + 本地 Git 导出和验签 | 可运行的密码与授权/Git 机制；非厂商流水线或生产授权 |
| 本地机制对照 | 同一九场景：作者自建 A 代理有 5 个未授权副作用案例、较强 B 代理有 1 个、CI-TRACE 研究协议 0 个；B 已包含业务/摘要/期限/撤销与一次性账本，其遗留问题是普通 Git 推送的检查后竞争和缺乏远端恢复 | 机制消融/故障注入，不是产品横评、真实误报率或独立盲测 |
| 本地性能 | 每场景 10 次；合法发布 p50 约 147 ms、p95 约 168 ms；ACK 丢失恢复 p50 约 225 ms、p95 约 401 ms（本次沙箱样本） | 同机 bare Git/SQLite/Python 的演示性时延；不代表 Gitee 网络或政企生产 |
| 真实 Gitee Web | 测试仓库 `liljunlin/test` 的专用分支 `ci-trace-r26-protected-20261017` 受保护，研发账号 Web 直写被拒；owner 审核并合并 [PR !1](https://gitee.com/liljunlin/test/pulls/1)；原始 merge commit `12401c28e176fbb0cd3ff920f5bc5936d98ba6fd` | 仅该测试仓库的 Web 权限与 PR 合并行为；不是 Git CLI receive-pack 拒绝 |
| 离线历史证明 | R27 归档固定 SHA-256 `0426dd4dca6e0222d5c168ab08a5efdddca91e60265ed4fb6544a4120f4307db`，固定 LAB 公钥指纹 `8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d`；原包有效、对象单字节改动拒绝 | LAB 签名、归档公开 API 与 Git 对象彼此一致；不是 Gitee 厂商数字签章 |
| 托管见证 | [GitHub Actions run 39031776743](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031776743) 的两个托管作业成功，签名[见证 56943794](https://github.com/junlin20011207/ci-trace-sandbox/attestations/56943794)，第二作业拒绝修改的主体 | 该 GitHub 工作流观察与签过特定字节；不是独立组织对发布的批准 |

R28 的 24 个公开 PR 方便样本中，13 个有合并前批准，3 个审批锚与最终 head 不同：1 个可确认后续提交，2 个只能判为历史上下文不一致。它只说明“曾有批准”不足以替代最终对象绑定，不能说明 GitHub 策略绕过，也不能用于 CI-TRACE 的漏报率估计。

## 4. 现有方案与创新边界

GitHub custom deployment protection rules、GitHub artifact attestations、Azure Approvals and Checks 已分别覆盖外部检查、来源证明和审批；SLSA Source v1.2 已明确最终修订及上下文特定审批。这些概念不是本作品的首创。CI-TRACE 的可演示组合在于将业务授权与制品/接收方/目标 Git 对象绑定，用原子 ref 创建抵抗检查后竞争，用远端对象确认恢复模糊 ACK，并把原始对象和 LAB 签名带出供离线核对。当前仍缺与商用系统统一威胁模型的端到端公平基线。

参考：GitHub [custom protection rules](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/create-custom-protection-rules)、[artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)；Microsoft [Approvals and checks](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals?view=azure-devops)；[SLSA Source v1.2](https://slsa.dev/spec/v1.2/source-requirements)。

## 5. 实施与评审演示

1. 展示威胁：错误接收方、目标 ref 抢占、ACK 丢失。
2. 执行单命令，说明九种本地场景和两种 SM2 契约的输出。查看 `run_output/summary.json` 的环境标记。
3. 离线复核真实 Gitee Web 历史对象；篡改一个临时副本后拒绝。展示公开 PR、保护分支历史和两次 GitHub 托管作业日志。
4. 解释三种证据层不能互相冒充，回答“为何已有外部审批/签名仍需要准确的目标对象与故障恢复”。

## 6. 局限与下一步

Gitee 的 Web 直写拒绝不能推出 Git CLI 推送拒绝；两个 Gitee 账号和实验签名者由同一人控制；R27 API 快照无厂商签名；主协议的 publisher 本地防线不能单独抵挡绕开它的直推；自建 Git hook 不可假设安装到 Gitee SaaS。缺少生产级独立审批、跨机器 mTLS、真实 CodeArts/Gitee Go 流水线、第三方盲标样本、长期运维和业务效用数据。托管 artifact 默认七天留存，应另行受控归档见证主体和 bundle。现阶段不主张商业密码合规认证、SLSA Source Level 3、生产部署或恰好一次业务效果。

## 7. 参赛声明与材料范围

本作品是参赛团队整理并运行的防御性研究原型，公开仓库与真实平台链接用于复核；所有本地故障注入、作者设计样本和平台行为在文中分列。提交材料不含生产账号凭据或实验私钥，不含学校/学院/导师身份。正式作品原创性声明须使用赛事附件模板，由参赛队员自行核对并签署；本稿不能代替该签署件。
