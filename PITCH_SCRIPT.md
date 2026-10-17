# CI-TRACE｜7 分钟讲述词与演示操作

**0:00–0:45，问题。** 代码审核通过，只说明某个提交经过技术评审。客户交付还要回答：哪份制品、给谁、落在哪个 Git 引用？换掉其中一个字段，原审批记录仍存在，但实际发布对象已不同。

**0:45–1:30，作品。** CI-TRACE 让签发方针对源 SHA、制品摘要、接收方、目标 ref、原基线和操作编号签一次短时授权。发布器核对这些字段，执行一次性预留，再用 Git 的 create-only 条件创建引用。一个条件不符就停下。

**1:30–2:30，故障。** 在普通的“先检查后推送”流程中，目标分支可能被抢先创建，随后普通推送覆盖它。我们的本地对照中，强业务基线在这一种场景仍产生未授权副作用，create-only 条件阻止了覆盖。另一种故障是 Git 已成功但 ACK 丢失；我们只读核对远端 commit、tree 和制品对象后恢复回执，不盲目重复推送。

**2:30–4:15，现场。** 在解压目录运行：

```sh
python3 ci_trace.py demo --output run_output
python3 ci_trace.py verify-gitee
```

打开 `run_output/summary.json`，依次看 `local_sm2_platform_contracts` 的两个本地契约、`local_git_protocol` 的 9/9、`archived_real_gitee_web_merge` 的有效归档及篡改拒绝。这里的 CodeArts/Gitee Go 是研究者自定义入口契约，绝不说成厂商原生流水线。

**4:15–5:30，真实平台锚点。** 打开 [Gitee !1](https://gitee.com/liljunlin/test/pulls/1)，说明专用受保护分支上的研发 Web 直写拒绝和 owner 合并。打开 [托管运行](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031776743)及[签名见证](https://github.com/junlin20011207/ci-trace-sandbox/attestations/56943794)，说明另一环境只读核查公开状态。R27 ZIP 让原始 Git 对象与 LAB 签名在离线环境重新验算。三种证据独立陈述。

**5:30–6:25，比较和定位。** 对照九种作者设计的本地场景，A、强 B、CI-TRACE 分别出现 5、1、0 个未授权副作用案例。B 已包括摘要、接收方、有效期、撤销及单次账本。我们针对剩余的目标 ref 竞争窗口与 ACK 恢复做机制验证。不能把这三个数字讲成产品排名或现实世界漏报率。

**6:25–7:00，边界与收束。** 本次交付有可运行源码、离线审计归档、真实 Gitee Web 合并、GitHub 托管只读见证。下一关是 Gitee Git CLI 的 receive-pack 权限实验、组织独立签发及厂商原生流水线接入。评委可从任何一条演示结果追到原始报告和代码。

## 现场追问的短答

- **开发者能绕过发布器吗？** 如果能直推目标 ref，就能。当前 Gitee 只验证了 Web 写入拒绝；Git CLI 仍待实测。
- **LAB SM2 是 Gitee 批准吗？** 不是。密钥由研究主体掌握，证明的是 LAB 归档内容一致性。
- **是“恰好一次”吗？** 授权预留和 ref 创建有明确约束；不承诺目标业务系统恰好一次处理。
- **已有部署审批为何还需要它？** 现有能力丰富。作品聚焦审批对象与最终 Git 引用的绑定，以及确认丢失后的对象级恢复。

## 演示环境

Python 3.11+、Git、OpenSSL 3.x（支持 SM2/SM3）、Python `cryptography`。主命令不需要网络或平台凭据。缺少依赖时，说明环境问题并引用已归档的运行证据，不能把历史日志冒充现场成功。
