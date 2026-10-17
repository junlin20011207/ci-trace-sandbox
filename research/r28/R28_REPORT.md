# CI-TRACE R28：跨平台托管见证与外部审批上下文样本

2026-10-17。研究仓库 `junlin20011207/ci-trace-sandbox`，测试仓库 `liljunlin/test`。本轮没有写 Gitee，也没有更改任一仓库的默认主分支。

## 三轮实验及结果

| 轮次 | 输入、方法 | 实际结果 | 可证明的范围 |
| --- | --- | --- | --- |
| 1：托管观察 | GitHub Actions [run 39031542239](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031542239) 的 Ubuntu 托管作业检查 R27 ZIP 的固定 SHA-256，执行离线 Git 对象/SM2 回执验证，再经公开 Gitee API 和 `git ls-remote` 回读 R26 PR、保护分支和当前 refs | producer job `117392819243` 成功，日志有 `REAL_GITEE_PUBLIC_READBACK_AND_R27_OFFLINE_PROOF_VALID=yes`、`GITEE_WRITE_PERFORMED=no` | 另一个平台在该时点实际只读观察到与 R27 历史归档一致的公开状态；仍是实验主体选择的脚本与断言 |
| 2：签名并独立作业复核 | producer 以 GitHub 托管工作流身份对 `witness.json` 做 [artifact attestation 56943454](https://github.com/junlin20011207/ci-trace-sandbox/attestations/56943454)；另一托管作业下载见证，限定证书工作流身份、源提交、源 ref 和非自托管运行器，复核 R27，并修改见证位后重验 | verifier job `117392882817` 成功，日志有 `SECOND_HOSTED_RUNNER_GITEE_WITNESS_AND_OBJECT_PROOF_VERIFIED=yes` 和 `SECOND_HOSTED_RUNNER_TAMPERED_WITNESS_REJECTED=yes` | 主体字节被变更时可拒绝；证明该 GitHub 工作流签过这些字节，不证明 Gitee 或组织审批方签过发布 |
| 3：独立公开 PR 上下文 | 固定 `pypa/pip`、`django/django`、`kubernetes/kubernetes`，每仓按最近更新列出 30 个 closed PR，取最先 8 个 merged；获取合并前 `APPROVED` review 的 `commit_id`，与最终 `head.sha` 比较 | 24 PR，13 个有可见审批，3 个审批锚与最终 head 不同；其中 [pip#14347](https://github.com/pypa/pip/pull/14347) 的批准时间 21:33:17Z，最终链上后续提交时间 21:42:57Z；[django#22144](https://github.com/django/django/pull/22144) 和 [#22141](https://github.com/django/django/pull/22141) 的审批锚不在最终提交列表 | 这是“只看曾经批准事件”代理规则的上下文反例；**不是** GitHub 产品的错误率、策略绕过、漏洞，也不是 CI-TRACE 的误报率 |

逐 PR 的匿名化元数据、SHA 和分类见 `external_pr_context_sample.json`。样本是方便抽样，仓库政策、review 撤销、自动化及合并规则未作对照；11 个未观察到审批的 PR 不能推断不合规。两个 django 例子仅能确认锚和最终历史不一致，不能从当前快照证明具体改写动作和审批有效性。pip 例子是确凿的时间/提交链顺序，仍不能证明其 GitHub 合并策略失效。

本轮原始工作流提交 `e9ab403566c2f91cf28137bd769403136883db27` 产生 run 39031542239。归档为 `research/r27/CI_TRACE_R27_Deep_Gitee_Proof.zip`，预期 SHA-256 `0426dd4dca6e0222d5c168ab08a5efdddca91e60265ed4fb6544a4120f4307db`；LAB 公钥外部锚 SHA-256 `8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d`。当次 Actions artifact ID `12100368360`，名 `ci-trace-r28-public-witness`，按设置仅保留七天；长期核查应保存签名 bundle、对象及运行日志于受控归档。日志及 attestation 链接可复核 GitHub 实际执行，不将本地负例当成平台行为。

第二次迭代把四个 `actions/*` 依赖固定到当时 `v4` tag 指向的确切提交，减少未来 tag 漂移；须以这次改动后的新 Actions 运行结果单独判断固定版本工作流是否成功。固定依赖仍无法防止控制研究分支和工作流内容的人写出虚假断言。

## 与现有能力比较后的定位

| 能力 | 已有公开基线 | CI-TRACE 目前可展示的增量与空缺 |
| --- | --- | --- |
| 发布前独立检查 | [GitHub custom deployment protection rules](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/create-custom-protection-rules) 可由 GitHub App 判断部署；[Azure Approvals and Checks](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals?view=azure-devops) 包括审批、REST/Azure Function 检查及 exclusive lock | “有外部审批”不是新颖点；CI-TRACE 应展示授权与制品、目标 Git ref 和单次操作的确切绑定，以及失败恢复 |
| 签名与来源 | [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) 已提供工作流签名证据 | R28 跨宿主见证和 R27 原始 Git 对象复算有组合价值；GitHub 签名只认证工作流执行/字节来源，不认证 Gitee 业务事实 |
| 源码最终状态 | [SLSA Source v1.2](https://slsa.dev/spec/v1.2/source-requirements) 已要求审批适用于最终修订和特定 repo/branch 上下文，并提出由源码控制系统产生源证明 | 精确 head/ref/上下文绑定与可携带的离线证据是待对比的实现；当前 LAB 回执不是源码控制系统的源证明，也不能自称达到 SLSA Source Level 3 |

## 证据等级和下一轮门槛

| 当前可信结论 | 尚欠的真实实验 |
| --- | --- |
| R26：Gitee 测试仓库专用保护分支，普通研发 Web 直写被拒，owner Web PR 合并；R27：该合并的归档原始对象和 LAB SM2 回执可离线交叉核验；R28：GitHub 托管双作业对 Gitee 当前公开状态作只读见证，签名主体篡改遭拒 | **Git CLI receive-pack**：以普通研发凭据真实推专用保护分支并留拒绝响应，再用与其控制域分离的发布身份成功推；当前 Web 拒绝不能替代 Git 协议拒绝 |
| 两账号由同一研究者控制；LAB 私钥由研究环境管理 | **独立组织授权主体**：把审批密钥/策略交给与发布者不同的主体，验证撤销、过期、重放、目标 ref 漂移、模糊 ACK 恢复；保存平台侧授权和审计 |
| 24 个公开 PR 的审批上下文观察，非安全标签 | **公平基线**：同一测试场景让现有 GitHub/Azure 原生策略和 CI-TRACE 分别执行，定义可判定的安全目标和盲测样本，再统计误报、漏报、耗时、运维代价 |

现阶段大赛陈述宜聚焦“确切对象与授权上下文绑定、跨平台可复核的实验方法”。不宣称发明外部审批、平台签名或 SLSA 源证明；不将当前真实 Web 实验扩展成 Git CLI、真实组织双人审批或生产验证。
