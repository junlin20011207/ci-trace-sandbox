# CI-TRACE R23 — 国产 DevOps 平台集成契约（已验证部分与待授权部分）

## 实际核对的官方能力

- 华为云 CodeArts Pipeline 的「第三方接口调用 v2」支持向第三方 HTTPS API 发送请求、携带自定义头、JSON 主体，并对非 2XX 返回码按失败处理。文档指出必须验证证书，不支持任意自签名无验证模式。可用作申请入口，但其存在不等于官方流水线具有 SM2 签名或 mTLS 客户端证书。
- CodeArts Pipeline 的 Webhook 配置支持外部 POST 触发。触发鉴权配置不等于独立业务审批。
- Gitee Go 支持 Gitee/GitHub 代码提交触发流水线；其 Release 插件支持创建 Release/Tag/附件以及在允许情况下覆盖。Gitee 通用 WebHook 密码为明文承载，不能等同于独立密码学身份签名。

## 我们的隔离接口

1. **不可信候选（CodeArts/Gitee Go）**：只提交发布申请 `source_platform/source_commit_sha/workflow_identity/artifact_sm3/recipient/target_repo/target_ref/operation_id`，没有实际 Gitee 写入凭据。
2. **独立审批端**：必须自行从可信来源校验 SCM 和制品数据，并在 issuer-only DB 中预批准严格相等的全部 subject；不能根据调用方「已批准」字段签名。R23 目前仅采用测试管理员预装 subject，未连接华为云 IAM 或 Gitee Go 的强身份 API。
3. **在线 mTLS 授权端**：真实 TLS 客户证书、CA 校验，SM2/SM3 签发及单次 SQLite 原子预留。本地隔离进程已真实验证，尚非不同物理主机/不同法人机构。
4. **受信发布端**：只在目标仓库真实分支保护、凭据由独立服务保管、无其它可绕过写入通道时具备强制性。R23 仅在一次性本地 bare Git 仓库执行真实创建专用 Git CAS 更新。
5. **离线审计**：SM2 验签使用带可信公钥 SHA-256 指纹的离线命令；签名历史回执不自动证明远端 Git 引用今天仍未改变。

## 允许的调用方式

CodeArts 的第三方接口插件可向面向公网且证书有效的 **外围桥接服务** 发送 POST JSON。但 CodeArts 插件的普通 API 调用不是 mTLS 工作负载证书证明，所以不能直接将其身份等同于 R23 受信 `ci-trace-publisher`。桥接服务需要按照预先注册的策略校验请求、核实源端状态，然后向独立授权端提交申请；不允许桥接端控制签发私钥或最终 Git 凭据。

Gitee Go 目前仅确认官方触发器及 Release 插件能力；要接入真实生产环境，还需要完成 Gitee Go 流水线配置、受保护变量权限、独立凭据、目标仓库保护和远端写入授权。公开读权限不等于写权限。

## 实际无法证明的部分

- 未执行任何有凭据的 Gitee Push / Release。绝不使用既往可能曝光的访问令牌。
- 未使用真实华为云 CodeArts Pipeline 项目执行插件；平台适配契约是研究者定义的可集成接口，不是假冒官方 webhook payload。
- 未由真实独立审批单位掌握密钥。
- 本地 localhost mTLS 不等于跨两个云主机真实生产网络；GitHub 云端的跨 runner 签名交接不等于在线双主机发布 RPC。
- 软件自行实现 SM2/SM3 不等于通过商用密码应用安全性评估。

## 官方来源

- https://support.huaweicloud.com/usermanual-pipeline/pipeline_01_0096.html
- https://support.huaweicloud.com/usermanual-pipeline/pipeline_01_0017.html
- https://help.gitee.com/enterprise/pipeline/source/trigger/
- https://blog.gitee.com/2026/01/23/gitee-go-release-plugin-auto-deploy-artifact/
- https://help.gitee.com/webhook/how-to-add-webhook/
- https://docs.openssl.org/3.5/man1/openssl-pkeyutl/
