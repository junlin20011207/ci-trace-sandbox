# CI-TRACE R23 · 面向国内 DevOps 平台的独立授权、国密签名与安全交付实验

**2026-10-12 · 研究原型，不是已落地的政企生产系统。** R23 继承 R22 的 Web 控制台、Git 发布协议、TLA+ 模型和基线实验，新增 `native_cn/` 国内平台适配与国密实验模块。

## 核心成果

- **CodeArts / Gitee Go 两种研究者自定义事件契约**：HMAC 桥接验证、失效事件拒绝、SQLite 可选 nonce 去重；在 issuer-own preapproval 前无法取得授权。**不是厂商原生事件已接入的证明**。
- **独立授权进程 + 真正的 TLS 双向证书校验**：localhost 受信实验 CA、身份为 `ci-trace-publisher` 的客户端证书；无证书或错误身份拒绝；SQLite 授权串行化。Issuer 与 publisher 是不同进程，但非独立物理主机或不同机构。
- **SM2/SM3 密码学**：使用实际 OpenSSL `SM2` 密钥、`SM3` 摘要、带 `distid=CI-TRACE-CN-R23` 的 SM2 签名/验签；签名覆盖来源平台、工作流标识、代码提交、制品、接收方、Git 基线和目标引用。
- **Git 发布与恢复**：真实本地 bare Git + create-only lease push；依赖实际远端 Git tree/parent/commit SHA 签发回执；模拟成功后 ACK 丢失、并发授权和拒绝重复确认。
- **独立离线回执验证**：无需 issuer 私钥，使用预先可信的 PEM 指纹验证 SM2 签名、批准主体绑定与结果证明。**历史签名无法保证当前远端分支没变**。
- **禁止真实 Gitee 写入**：运行发布函数必须检测一次性 bare Git 测试仓库标记 `CI_TRACE_DISPOSABLE_LOCAL_LAB_ONLY`；真实 Gitee URL 被明确拒绝。无 Gitee Token 存储在本包。

## 运行方式（可在隔离沙箱中直接完成）

依赖：Python 3.11+、Git、OpenSSL 3.x（支持 SM2/SM3）、`pytest` 和 R22 的 `requirements.txt`。首次验证见：

```bash
# R23 新增 48 项测试（两种自定义入口契约、SM2/SM3、mTLS、真实本地 Git）
python -m unittest native_cn.test_native native_cn.test_adapter native_cn.test_bridge_integration -v

# 生成可交付、纯公钥材料；各自采用真实实验 SM2 签名
python -m native_cn.demo_export --platform CODEARTS --output results_r23/offline_codearts
python -m native_cn.demo_export --platform GITEE_GO --output results_r23/offline_giteego

# 离线验证，不依赖 issuer 进程，不需要任何生产令牌
python -m native_cn.offline_verify \
  --grant results_r23/offline_codearts/grant.json \
  --receipt results_r23/offline_codearts/receipt.json \
  --subject results_r23/offline_codearts/subject.json \
  --issuer-public results_r23/offline_codearts/issuer_public.pem \
  --trusted-sha256 <事先通过可信通道取得的公钥文件SHA-256指纹>

# R22 回归验证
python -m pytest -q tests/test_product.py
python -m unittest discover -s core -p test_protocol.py
# root隔离容器里（由专门实验环境执行，不要在普通生产机运行）
CI_TRACE_TEST_UID_LAB=1 PYTHONPATH="$PWD:$PWD/core" python -m unittest -v core.test_ipc_lab
```

**重要：** `VERIFICATION.json` 中展示的公钥指纹是在同一实验包中生成的，能够用于示范离线验签，却不构成真实独立机构的信任锚；生产环境的信任根必须通过独立可信通道固定。

## 云端真实验证

GitHub-hosted Actions 在两个不同托管运行器之间传递 SM2 签名材料：发行运行器生成密钥、签名，并通过 GitHub attestation 记录公钥的工作流来源；第二运行器核对工作流身份、源 SHA/ref，使用 SM2/SM3 公钥验签并拒绝篡改。另有真实 Gitee **匿名只读** `ls-remote` 连接。对应的是远端研究环境，不是 CodeArts/Gitee Go 产品本身的流水线任务。

## 与现有国内方案的技术定位

CodeArts 已有人工审核、第三方 API 插件与发布功能；Gitee Go 已有提交触发与 Release 插件。**CI-TRACE 的研究增量**是跨平台操作级业务批准绑定、授权原子预留、Git 原子引用限制和经远端对象校验的恢复回执。R23 并未做国内厂商完整原生功能的公平对照测试，因此不能主张已超越其商业产品。

完整事实和未完成项见 `ROUND23_REPORT.md`、`native_cn/INTEGRATION_CONTRACT.md`。R22 原项目 `README.md` 和 Web 控制台仍可使用。
