# CI-TRACE R27：真实 Gitee Web 合并证据的离线交叉核验

2026-10-17（Asia/Shanghai）。实验目标：在不修改 Gitee 测试仓库任何 ref、不修改 GitHub `main` 的前提下，收紧 R26 实验回执的历史证据一致性；始终区分真实平台观察与本地故障注入。

## 假设与四轮实测

| 轮次 | 假设与操作 | 结果 | 性质 |
| --- | --- | --- | --- |
| 1：寻找误判 | 在临时副本中把 R26 `merge_commit` 改为全零 SHA，实验密钥重签回执，其余“祖先关系”布尔值保留真 | R26 原验签器仍返回 `VALID_SIGNED_LAB_OBSERVATION...`，证明它不独立计算 Git 图 | **本地逻辑反例**；未向 Gitee 写入或伪称 Gitee 发生过这个提交 |
| 2：重算对象 | 从此前实际只读 Git fetch 保留的仓库导出真实 base/source/merge commit、base/source tree、README blob 六个原始对象；逐个重算 Git 对象 SHA，解析 parent/tree，并核对真实 Gitee API 的 PR、保护分支、master | 原始真实证据通过；修改对象、PR 状态、保护位或 master 的中间版负例拒绝 | 实际平台历史对象 + **本地变体** |
| 3：固定归档 | 对六个原始对象、对象清单和三个 API 快照做 SHA-256 清单，用同一实验 SM2 密钥签署新的 R27 补充回执，并绑定 R26 回执摘要 | 最终版原始包通过；7 项修改、误记或替换锚定条件均拒绝 | 同一 LAB 观察主体，不是 Gitee 厂商签名 |
| 4：状态回查 | 用公开 API 和 `git ls-remote` 只读核对现在的 PR、保护标记、master、控制分支、目标分支 | 2026-10-17 20:05:16（Asia/Shanghai）仍匹配历史合并 | **真实 Gitee 当前回读**，与离线历史验签分开 |

第 1 轮揭示的信任边界很具体：R26 可以确认“可信 LAB 签名者签过这个 JSON”，但若观察者误记或故意声称不存在的 Git 对象，它无法自己发现。R27 的对象核验能发现与已存对象不一致的签名误记。增强程序解析真实 merge commit 的两个父提交 `c6a87f2f92a4adf7ebf72a0161f915c7a91a781c`、`e27bc918ceab6ef0233a2acbef189af67b333a77`，确认源提交直接基于原基线、源树和合并树都为 `46c72b5db40c158f60802dcf2128c527c64cf245`，基线与源树只有根目录 `README.md` 的 blob 不同。README 原始 blob 与已签 SM3 制品字节完全一致。

最终增强验签结果：`VALID_LAB_OBSERVATION_WITH_OFFLINE_GIT_OBJECT_AND_API_CONSISTENCY`。最终版的 7 项负例包含原始对象位改、API 保护位改、承诺文件改、补充回执签名改、签名者误记合并 SHA、签名者误记保护标志以及替换公钥。具体输入和输出见 `round3_signed_archive_tests.json`。第 2 轮 `round2_consistency_tests.json` 是**加入补充签名之前**的中间版记录；其返回的错误码与最终版不完全相同。

## 可复核输入与命令

- 真实 Gitee PR：[liljunlin/test !1](https://gitee.com/liljunlin/test/pulls/1)。R26 已完成该 Web PR 合并，并保存了 API 响应及只读 Git 回读。
- 公钥 SHA-256 锚：`8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d`。务必从可信渠道另行固定，不可只读取待验压缩包内的值。
- `proof/objects/*.raw` 为真实读取的 Git 对象正文；`proof/object_manifest.json` 给出类型、对象 ID、大小和 SHA-256；`snapshots/*.json` 是此前真实公网 API 响应的原始包装记录。
- `proposal/` 原样包含 R26 的 SM2 grant、回执、签名公钥和制品。R27 另有 `proof_commitment.json` 与 `r27_receipt.json`，未修改 R26 已签文件。

```sh
python3 verify_deep.py --bundle . --trusted-public-sha256 8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d
python3 verify_live_ref.py --bundle . --trusted-public-sha256 8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d
```

第一条不联网；第二条只读联网，并且只在执行时刻报告当前状态。需要 Python 3.9+、Git、OpenSSL 3 支持 SM2/SM3。归档的 SHA-256 清单用于核对 ZIP 解包完整性。两条命令都不会发送凭据或向 Gitee 写入。

## 尚未跨越的边界

1. Gitee API 原始 JSON 没有厂商数字签章。R27 只能确认归档快照与已签 LAB 观察、Git 内容寻址对象彼此一致；不能把它升级为独立 Gitee 证明。签名者若能完全伪造自洽的 Git 对象和 API 快照，单靠同一实验密钥不能识破。
2. 两个平台账号都由同一研究者控制，临时 LAB 私钥仍由同一研究环境掌握；不构成组织审批人与发布者独立控制。
3. 本轮没有 Git CLI `push` 或 Gitee `receive-pack` 授权试验，也没有 CodeArts/Gitee Go 真实流水线、双机 mTLS、生产审批或商用密码合规认证。
4. SHA-1 是所测 Gitee 仓库的 Git 对象标识；R27 额外以已签 SHA-256 承诺固定收到的确切对象字节，仍依赖 LAB 签名者事前正确采集及保管信任锚。
5. 后续远端 ref 可以变化；离线程序只证明历史归档内部一致。在线脚本需重跑才能报告最新状态。

Git 对象正文、tree 中 blob 引用、commit 中 tree/parent 的格式依据 [Git 官方对象说明](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) 与 [git-cat-file 文档](https://git-scm.com/docs/git-cat-file)。Gitee 官方帮助将分支推送和 Web 文件修改都列为流水线代码提交触发方式，但本实验只把 Web 拒绝计作 Web 路径结果：[代码提交触发](https://help.gitee.com/enterprise/pipeline/source/trigger/)。
