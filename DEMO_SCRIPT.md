# 评审演示：7 分钟主线与追问准备

## 7 分钟主线

| 时间 | 操作 | 讲清的事实 |
| --- | --- | --- |
| 0:00–0:45 | 问题页：代码评审通过不等于接收方发布授权；ACK 丢失与抢占目标 ref | 威胁模型是业务操作级授权与 Git 发布事实 |
| 0:45–1:45 | 展示架构：申请主体、SM2 issuer、mTLS publisher、Git 对象、离线审计 | R23 是本地分进程实验；非 Gitee/CodeArts 原生上线 |
| 1:45–3:15 | 运行 `python3 ci_trace.py demo --output run_output`；看 9/9 与两种本地国密契约 | 错接收方、换制品、撤销、重放、64 路争用、ref 碰撞、ACK 丢失均有执行证据 |
| 3:15–4:15 | 看 `archived_real_gitee_web_merge`：归档原包有效、临时改动 Git 对象拒绝 | 真实 Gitee Web 合并是历史事实；密钥签名属于 LAB |
| 4:15–5:15 | 打开 [Gitee !1](https://gitee.com/liljunlin/test/pulls/1)、[托管复跑](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031776743)、[签名见证](https://github.com/junlin20011207/ci-trace-sandbox/attestations/56943794) | 实际平台观察与本地模型分列；GitHub 签名的是工作流见证 |
| 5:15–6:20 | 展示作者构建的强 B 基线：一次性账本和业务绑定仍挡不住普通 Git 推送的检查后 ref 抢占 | 创新表述聚焦确切对象、原子 ref 与远端恢复，而非“首次实现外部审批” |
| 6:20–7:00 | 说出限制和下一验证门槛 | 尚无真实 Git CLI 拒绝、独立组织 signer、厂商签章和生产接入 |

## 六个高概率追问

1. **研发直接推分支能绕开 publisher 吗？** 如果受保护分支未把写权限限制给独立发布身份，能；本地 publisher 校验不阻止直推。R26 只证实了 Web 拒绝，Git CLI receive-pack 尚未实测。
2. **SM2 回执意味着 Gitee 批准了吗？** 不意味着。私钥由实验主体掌握；R27 证明归档对象与 LAB 签名的一致性，GitHub R28 见证的是只读公开状态。
3. **与 GitHub/Azure 原生功能相比，创新在哪里？** 原生服务已能做外部审批和制品来源证明。这里的研究组合是目标 ref/原基线/接收方/制品/单次操作绑定，create-only Git 更新，以及模糊 ACK 后的对象级恢复；尚未完成公平产品横评。
4. **9 个场景的“零漏报”可信吗？** 不能称为漏报率。它们是作者构造的机制故障注入，没有独立业务真值标签。
5. **“恰好一次”成立吗？** 只证明研究环境下一次授权预留与有依据的回执恢复；不保证远端接收方的业务处理恰好一次成功。
6. **是否达到商用国密或 SLSA Source Level 3？** 没有此类认证或平台发行的 Source Provenance；使用 OpenSSL SM2/SM3 实际执行不等于合规认证。

## 故障预案

主机无法联网时，主命令仍离线运行；用 PDF 中的公开 URL 和预存 R26–R28 报告解释历史平台行为。缺少 FastAPI/pytest 时不启动旧 Web UI；主命令只需 `cryptography`、Git、OpenSSL。若 SM2 实验失败，展示明确报错和已归档的真实运行日志，不把旧日志冒充现场成功。现场不要输入个人平台凭据。
