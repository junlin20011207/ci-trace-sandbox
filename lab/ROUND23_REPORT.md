# CI-TRACE R23 技术报告：国产 DevOps 操作级授权与可验证交付

报告日期：2026-10-12。研究状态：实际实验完成 / 真实国内平台生产接入未完成。

## 研究目标与国内安全场景

将来自 CodeArts 或 Gitee Go 的发布请求视为**不可信候选**，由独立授权域核实来源与预先批准的操作主体，在真实 mTLS 会话内签发 SM2/SM3 一次性授权。发布器必须在独立保管 Git 写权限前提下验证指定制品、接收方、来源、目标、有效期和使用次数；Git 侧执行创建专用引用原子更新；发行后由可信服务验证真实 Git 对象并签发可离线验证的签名回执。

对标国内高安全软件供应链场景，包括关键系统升级、面向不同政企接收方的软件制品交付、内网自主管控/审计。此处是**设计目标**，不是在任何政企生产环境完成的验收。

## R23 新增实际结果

| 项目 | 验证方法 | 结果 | 界限 |
|---|---|---|---|
| 国产密码 | OpenSSL 3.5.5 SM2 keygen, SM3 digest, SM2 user-ID sign / verify | 真实运算通过；篡改、伪造/替代密钥或算法拒绝 | 未经商密合规测评 |
| HTTPS 可信通信 | 单机不同进程 + TLS CA / mTLS client certificate | 无证书及错误 CN 被拒绝 | 同机器实验 CA，不是双物理主机 |
| 独立授权账本 | 发行进程 SQLite `BEGIN IMMEDIATE`，签名授权 | 32并发仅一个取得预留；预留前撤销拒绝；发布端不能执行管理员撤销 | 研究者控制实验管理员身份 |
| 国产平台入口 | 自定义 CodeArts / Gitee Go bridge payload，HMAC 请求校验，nonce 回放限制 | 两平台契约均完成本地端到端演示 | 不是官方流水线真实触发，也不证明官方源身份 |
| 发布原子性 | 真实 Git bare repository，create-only lease ref | 抢占目标分支不能被覆盖 | 本地仓库，Gitee 仍只读 |
| 故障恢复 | 推送完成后丢失 ACK，远端树/父提交/目标引用校验 | 可恢复并签发独立 SM2 历史回执 | 没有分布式原子事务或强承诺“恰好一次” |
| 离线独立审计 | 独立 CLI 以 pinned PEM SHA-256 fingerprint 校验 SM2 回执及 grant binding | 正例通过；指纹不符返回 exit code 2 | 公钥必须通过独立可信渠道锚定 |
| 本地 R23 回归 | `native_cn.test_native`, `test_adapter`, `test_bridge_integration` | **48项通过** | 研究者设计，非独立业务样本 |
| 原 R22 产品核心回归 | `pytest tests/test_product.py`，`core/test_protocol.py`，Linux UID `core.test_ipc_lab` | **4 + 30 + 7 项通过** | UID 测试仍共享实验机 root |
| 真实云端国密与 Gitee | GitHub hosted workflow | 3作业成功：SM2 issuer、独立运行器验证、Gitee只读 | 不等于 CodeArts 云任务 / Gitee 真实写入 |

## 反例与工程修正

1. 初次 mTLS 使用的短期实验 CA 缺失正确的 Key Usage，OpenSSL 3.5 严格校验失败；补齐 `CA:TRUE` 和证书用途扩展后通过。
2. 初版 mTLS API 让 publisher 身份可调用 `/revoke`，虽然只能执行拒绝服务，但违反管理员职责隔离；改为 admin-only 拒绝，并让测试管理员直接更改独立 DB 模拟撤销。
3. 初版国产化绑定未单独标识真实来源平台、工作流身份及源代码提交；已纳入 SM2 签名主体并在回执离线核对。
4. 初版桥接事件可在90秒时窗内重复提交；增加可选 SQLite 持久化 nonce 去重，发行端仍独立限制 grant 消耗。
5. Git 发行函数明确只允许包含 `CI_TRACE_DISPOSABLE_LOCAL_LAB_ONLY` 标记的本地实验 bare repository，防止因字符串误填而触发未经授权的真实 Git 操作。
6. 初始 GitHub-hosted Gitee ref SHA 校验曾使用 `awk ... || true` 降低断言严格性；改用 Python 解析后在后续完整云端运行通过。

## 国内厂商能力与我们比较的结论

**华为 CodeArts** 官方已具备流水线人工审核、第三方 API 调用、Webhook 触发和并发调度；**Gitee Go** 已提供 Gitee/GitHub 代码触发和 Release 插件，并明确支持在配置允许时更新/覆盖发布。我们的创新不能写为“首次外部审批”“国内尚无发布控制”。

可建立的精确技术价值：安全审批主体和 Git 实际引用变更的一致性，在实际远端提交已经成功但 ACK 丢失时验证完成状态；已在本地原型和 R22 reference baseline 中证明。需要进一步在合法权限的真实 CodeArts/Gitee Go/Gitee 组合中运行才能据此作出国内商业竞品优越性判断。

国际对标基于 GitHub External Deployment Protection Rules、Azure DevOps Approvals/Checks、in-toto/Sigstore 的成熟能力。它们可用扩展策略实现大多数单项控制；不能声称 CI-TRACE 对其绝对领先。

## 公开可独立复核的远端证据

- R22 真实云端模型/数据/跨机 Sigstore: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38264403530
- R23 真实云端 SM2/SM3/第二 runner + Gitee read-only: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38269532979
- R23 离线样本：`results_r23/offline_codearts` 与 `results_r23/offline_giteego`，仅公钥与签名材料，无实验私钥。

## 尚未完成的真实生产事项

1. CodeArts/Gitee Go 实际项目流水线触发；现有桥接器只对应自定义请求契约，并不假冒官方 payload。
2. 跨两个不同管理员/物理云主机运行的在线 mTLS 授权机关和发布执行器；已有的是本地进程 mTLS 和云端两个托管运行器的签名交接。
3. 真实 Gitee 写入与可证明的分支保护强制性；当前无凭据，只读连接成功，所有发布在 disposable Git 仓库。
4. 第三方真实单位批准、独立业务越权事件标签与大规模业务验收。
5. 国密产品或生产系统的合规检测；本研究用 OpenSSL 算法实现，不构成标准认证。

## 主要官方资料

- CodeArts 第三方 API 插件：https://support.huaweicloud.com/usermanual-pipeline/pipeline_01_0096.html
- CodeArts Webhook 和触发策略：https://support.huaweicloud.com/usermanual-pipeline/pipeline_01_0017.html
- CodeArts 人工审核：https://support.huaweicloud.com/usermanual-pipeline/pipeline_01_0090.html
- Gitee Go 代码提交触发：https://help.gitee.com/enterprise/pipeline/source/trigger/
- Gitee Go Release 插件：https://blog.gitee.com/2026/01/23/gitee-go-release-plugin-auto-deploy-artifact/
- Gitee Webhook：https://help.gitee.com/webhook/how-to-add-webhook/
- OpenSSL SM2/SM3 官方参数：https://docs.openssl.org/3.5/man1/openssl-pkeyutl/
