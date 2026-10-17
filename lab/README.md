# CI-TRACE R22：操作级授权与安全发布 · 完整可执行研究样机

**版本：2026-10-12，实验研究版。** 已整合授权发行、Ed25519签名、SQLite在线原子预留、Git create-only发布、远端校验、崩溃后只读恢复、Web控制台，以及强基线实验和有限状态形式化验证。

> **严禁把这个演示程序当成生产安全网关。** Web界面的实验管理员持有临时 LAB 私钥；所有目标“Gitee”字段只是协议绑定用的字符串，实际发布仅发生在临时本地裸 Git 仓库；没有真实 Gitee token、企业密钥或外部审批机构。详见 `SECURITY_BOUNDARIES.md`。

## 立即运行

需求：Python 3.11+、Git、Linux/macOS（UID权限实验仅支持Linux disposable root容器）。

```bash
python -m pip install -r requirements.txt
python app.py
```

在同一电脑访问 `http://127.0.0.1:8765`。产品默认只绑定本地环回地址，**请勿对公网开放**。

亦可不启动网页，直接进行全流程演示：

```bash
python demo_engine.py --all
python demo_engine.py --scenario crash_recovery
bash run_all.sh
# 以下命令只能在一次性 root Linux 容器中执行：
CI_TRACE_TEST_UID_LAB=1 bash run_all.sh
```

## 已实现的九种安全演示

| 场景 | 预期效果 |
|---|---|
| legitimate | 有批准书，实际本地 Git 发布，回执核验成功 |
| wrong_recipient | 企图交付客户B，主体不一致拒绝 |
| payload_swap | 制品摘要变化拒绝 |
| expired | 实时授权过期拒绝 |
| revoked | 先撤销后预留拒绝 |
| replay | 第二次执行只读恢复/确认，不能再次发布 |
| concurrent | 64个在线并发预留，严格单赢家 |
| crash_recovery | 真正 Git push 后进程 exit(91)，凭远端证明恢复 |
| branch_collision | 目标分支提前创建，拒绝覆盖 |

## 项目结构

- `app.py` + `ui/index.html`：可交互 Web 控制台和 HTTP API（实验白名单；不接受任意 shell/git 指令）。
- `demo_engine.py`：9个端到端实验调度器，隔离真实裸 Git 仓库、签名和 SQLite。
- `protocol.py` / `release_gate.py`：第21轮修复后的授权-发布内核，保留六类漏洞修复。
- `core/ipc_lab.py` + `core/test_ipc_lab.py`：跨 Linux UID 的独立授权进程与权限检查。
- `experiments/paired_baselines.py`：研究者实现的 A（代码审批代理）、B（强外部审批代理）以及 CI-TRACE 配对比较。**它们不是 GitHub/GitLab 官方产品测评。**
- `experiments/latency.py`：9场景每种10次发布核心步骤延迟测量；`experiments/baseline_latency.py`：B/C各10次全场景总墙钟耗时（含临时仓库初始化）。
- `formal/exhaustive.py`：显式状态空间遍历+不安全旧方案最短竞态反例。
- `formal/CITraceR22.tla` / `.cfg`：真实 TLC 可执行规范；云端已经验证36个不同状态。
- `third_party/README.md`：公开第三方数据的来源、固定提交、聚合结果和许可界限。
- `results/`：原始 JSON、测试输出、延迟数组和 GitHub证据转录。
- `SECURITY_BOUNDARIES.md`：生产前必须满足的信任假设与尚未实现的控制。
- `ROUND22_REPORT.md`：技术与竞赛研究报告。

## 真实云端与外部实验

[GitHub Actions R22 云端运行 #38263320485](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38263320485) ：**6个作业成功**：

1. 在托管GitHub运行器真实测试Git引用竞态、SQLite并发、Gitee只读Git连接。
2. 独立第三方研究数据：2722份公开工作流元数据，448条人工弱点标注/50份不同工作流。
3. 公开GitHub PR审查事件：Flask、Node.js、Rust真实PR审核元数据，仅提供实际审查背景，不是发布授权标签。
4. TLA+ TLC v1.7.4：36个不同可达状态，所定义不变量均通过。
5. GitHub+Sigstore签发短期来源证明，并通过GitHub CLI验签。
6. 另一台GitHub托管运行器下载证据，严格验证签名工作流身份、源SHA、分支，篡改字节后必须拒绝。

注意：真实Gitee仅测试无凭据读取；没有写入。双运行器实验是 **签名制品传输与身份核验**，不是发布业务两机mTLS执行链。

## 不应宣称的结果

- 没有任何第三方企业正式担任本项目批准机构，也没有生产发布凭据。
- 第三方工作流弱点标签不能当作真实业务越权事件；不能凭这些数据宣称生产误报率、漏报率或ROI。
- 强基线对照是**我们独立实现的明确对照程序**，不是所有 GitHub/GitLab 原生安全控制的真实交付测评。
- TLA+模型只覆盖有限状态抽象；不能证明实际Git服务、网络或者程序没有所有漏洞。
- 本地签名与进程隔离不能替代外部可信审批策略、受保护Git分支和真实密钥托管。

许可证和第三方代码：当前研究脚本系本轮生成，历史R21代码随原来源一并打包。`third_party`仅保存统计与链接，不重新分发未确认许可的第三方原始数据。
