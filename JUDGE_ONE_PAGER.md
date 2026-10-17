# CI-TRACE｜评委速览

**一句话**：让业务授权绑定到实际交付的制品、接收方和 Git 引用；当推送确认丢失时，依据远端对象恢复回执，并允许事后离线核验。

## 现场先看什么

| 评委要判断的事 | 作品中的可检查对象 | 结论边界 |
| --- | --- | --- |
 能否演示具体安全机制 | `python3 ci_trace.py demo --output run_output`，再读 `run_output/summary.json` | 本地一次性 Git 仓库，9 个作者设计场景通过 |
 是否有真实平台行为 | Gitee [测试 PR !1](https://gitee.com/liljunlin/test/pulls/1)，专用保护分支 `ci-trace-r26-protected-20261017` | 研发 Web 直写遭拒、owner Web 合并；未测 Git CLI receive-pack |
 历史结果能否脱机核查 | `python3 ci_trace.py verify-gitee` 与 R27 归档 | Git 原始对象与 LAB SM2 回执核对，篡改副本拒绝；Gitee API 快照无厂商签名 |
 第三方环境是否复核过公开状态 | [GitHub Actions run](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031776743) 与[托管证明](https://github.com/junlin20011207/ci-trace-sandbox/attestations/56943794) | GitHub 工作流见证；不是独立业务审批 |

## 作品独到之处

1. 将批准范围落实到源提交、制品摘要、接收方、目标 ref、原基线和一次操作。
2. 一次性预留接上 Git create-only 原子更新，避免检查后被抢占的 ref 被普通推送覆盖。
3. ACK 丢失时读取远端 commit、tree 和对象后再出回执；归档可在无平台凭据时核验。

GitHub、Azure 等已有审批和证明能力；作品主张的是这一业务对象绑定、Git 原子条件、故障恢复与离线审计的组合，不主张首创审批或签名。

## 展示顺序

先用 12 页匿名演示稿讲 7 分钟，再现场运行主命令，展示错接收方、ref 抢占与 ACK 恢复，最后打开公开平台记录。完整算法、测试方法及限制在官方格式的匿名作品报告与源码包中。

## 尚待验证

Git CLI 在 Gitee SaaS 保护分支的拒绝与独立发布成功、真正组织独立的签发者、厂商原生流水线和生产环境时延尚未完成。当前结论是可复现的研究作品，不是生产认证。
