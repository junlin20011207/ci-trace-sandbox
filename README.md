# CI-TRACE 参赛整合作品（研究版）

**一句话：** 将一次发布的制品摘要、接收方、Git 目标引用与基线绑定到限时授权；在一次性预留后执行原子 Git 引用创建，依据真实远端对象恢复模糊结果，并输出可离线核验的历史证据。

本包区分三种证据：本地隔离的完整控制链路、Gitee 测试仓库的真实 Web 发布历史、GitHub 托管的公开状态见证。它们不是同一次跨组织生产发布。

## 快速运行

环境：Linux/macOS，Python 3.11+、Git、OpenSSL 3.x（支持 SM2/SM3），Python 包 `cryptography`。如需运行可选 Web UI 和 pytest 产品测试，再安装 `lab/requirements.txt` 中的全部依赖。下述主命令无需 FastAPI/pytest，也无需网络或 Gitee 凭据。

```sh
python3 ci_trace.py demo --output run_output
python3 ci_trace.py verify-gitee
```

第一条执行：

1. 在一次性目录中分别跑 CodeArts、Gitee Go **研究者自定义契约**的本地 SM2/SM3 + mTLS + Git 发布实验；只导出公钥证明，私钥不进输出。
2. 跑九种本地 Git 协议场景，包括错误接收方、制品替换、撤销、过期、重放、64 路授权争用、ACK 丢失恢复和引用碰撞。
3. 校验归档中 R26 真实 Gitee Web 合并的原始 Git 对象与 LAB SM2 回执；在临时副本中改动一个对象，确认离线验签拒绝。此步骤只处理已有归档，不访问或写入 Gitee。
4. 生成 `run_output/summary.json`。该文件严格标注每一结果的执行环境和未执行的在线检查。

运行包主目录的 `ci_trace.py` 不接受仓库 URL、令牌或目标分支作为参数；本地发布实验自身也拒绝未标记的一次性 bare Git 仓库。**不要把实验私钥、Gitee SSH 私钥或任何 Token 放入提交包。**

## 作品组成

| 目录 | 作用和真实性 |
| --- | --- |
| `lab/native_cn` | R23 本地国密、双向 TLS 和自定义平台适配契约；非厂商原生云流水线 |
| `lab/protocol.py`、`lab/demo_engine.py`、`lab/formal` | R22 本地授权与 Git 原子发布协议、故障恢复和模型/场景 |
| `evidence/r27/CI_TRACE_R27_Deep_Gitee_Proof.zip` | 真实 Gitee Web 合并的历史对象与只读公开 API 快照；LAB 签名，不是 Gitee 厂商签章 |
| `evidence/r28` | GitHub 托管只读见证与 24 PR 上下文方便样本的报告 |
| `OFFICIAL_ENTRY_REPORT.md` | 按官方附件章节组织的参赛正文源稿；PDF 是匿名提交排版件 |

R25 本地 Git 服务器端 hook 的研究结论只作为可选扩展，**不是** Gitee SaaS 可安装该 hook 的证明。原始各轮说明仍在 `lab/`；以本 README 和 `OFFICIAL_ENTRY_REPORT.md` 的限制陈述为提交口径。PDF 按官方附件的摘要、五章、参考文献与填写说明页编排，正文为 12 磅宋体风格嵌入字库、18 磅行距；摘要 258 字。正式原创性声明仍须由参赛团队签名。

## 进一步复核

```sh
cd lab
python3 -m unittest native_cn.test_native native_cn.test_adapter native_cn.test_bridge_integration -q
python3 -m unittest discover -s core -p test_protocol.py -q
python3 experiments/paired_baselines.py
python3 experiments/latency.py
```

最后两个脚本运行的 A/B/C 对照是**作者自建本地机制**，不能解释为 GitHub、Azure、CodeArts 或 Gitee 产品的实测安全排名。九场景与时延均为隔离环境数据，不能推算生产误报率或网络时延。

## 公共平台证据

- Gitee 测试 PR：[liljunlin/test !1](https://gitee.com/liljunlin/test/pulls/1)，合并到专用保护分支；不是默认主分支。
- GitHub Actions [R28 固定依赖复跑](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031776743)与[托管签名见证](https://github.com/junlin20011207/ci-trace-sandbox/attestations/56943794)。
- 实验细节与限制：`evidence/r27/R27_REPORT.md`、`evidence/r28/R28_REPORT.md`；七日留存的 Actions artifact 不应成为长期唯一证据。

参赛文档和可执行包不包含队员学校、学院、导师等身份信息。官方原创性声明模板仍需由参赛团队本人核对、填写和签署，不在本程序中代签。
