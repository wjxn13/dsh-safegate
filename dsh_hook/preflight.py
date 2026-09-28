# -*- coding: utf-8 -*-
"""挂载前/挂载后的综合预检：逐项核对 DSH 加载 hook 时需要的每一个条件。

用法：`python preflight.py`

⚠️ **不要加 `-S`** —— 本脚本要 `import yaml` 解析 `cordis.patch.yml`，
   而 `-S` 跳过 site 初始化 ⇒ 装在 site-packages 里的 pyyaml 会看不见。
   （其余脚本为提速都带 `-S`，所以这里很容易顺手加上；本脚本已为此加了明确的报错。）
   若一定要带 `-S`，得先 `python -S -m pip install pyyaml`。

为什么要有这个脚本：DSH 的插件加载失败是**静默**的 ——
本机 `cordis.patch.yml` 的注释里已经踩过一次
（「WorkBuddy 升级 node 后目录名会变，两个 MCP 会静默起不来」）。
⇒ 改完配置不能靠"看起来没错"，要靠逐项断言。
"""

import importlib.util
import json
import os
import re
import sys

# ⚠️ 控制台编码兜底（模块级，覆盖所有入口）：
#    中文 Windows 控制台默认 cp936(GBK)，**能编码汉字但编码不了 emoji**，
#    而本脚本的'失败'分支会打印 ❌ ⇒ 恰好在你最需要看结果的时候崩掉。
#    真实事故（2026-09-24）：同类问题在 gate_hook.py 上发生过，详见那里的长注释。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                  # noqa: BLE001
        pass

try:
    import yaml
except ModuleNotFoundError:
    # ⚠️ 这条错误信息刻意写长：裸的 "No module named 'yaml'" 会让人以为环境坏了，
    #    而真实原因多半只是**多打了一个 `-S`**。
    #    ⇒ 错误信息必须能指路，否则它比没有信息更贵（会把人送去修错的地方）。
    print("✗ 缺 pyyaml：本脚本要解析 cordis.patch.yml，必须能 import yaml。")
    print("  最常见原因：用了 `python -S` —— 它跳过 site 初始化，")
    print("  已装在 site-packages 里的包会看不见。")
    print("  ⇒ 去掉 `-S` 再跑：python preflight.py")
    print("  （或装给它：python -m pip install pyyaml）")
    raise SystemExit(2)

# ══════════════════════════════════════════════════════════════════════
#  路径：一律**算出来**，不写死用户名
# ══════════════════════════════════════════════════════════════════════
#  为什么不能写死 `C:/Users/<某人>/.dsh`：本文件要公开，写死就是把作者的用户名
#  发布出去；更重要的是**换了机器就静默失效**（检查会全部落在不存在的路径上，
#  然后报一堆假错）。⇒ 一律从环境变量 / `~` 推导，并允许环境变量覆盖。
_HOME = os.path.expanduser("~")
DSH_HOME = os.environ.get("DSH_HOME") or os.path.join(_HOME, ".dsh")
DSH_NODE_MODULES = os.environ.get("DSH_NODE_MODULES") or os.path.join(DSH_HOME, "profiles", "node_modules")

CORDS_PATCH = os.path.join(DSH_HOME, "cordis.patch.yml")
PLUGIN_ENTRY = os.path.join(DSH_NODE_MODULES, "@deepseek-ai", "dsh-hooks-claude-code", "lib", "index.js")
PLUGIN_NAME = "@deepseek-ai/dsh-hooks-claude-code"
PLUGIN_ID = "dsh-gate-hook"

_ok = True


def chk(label: str, cond: bool, extra: str = "") -> None:
    global _ok
    mark = "[OK] " if cond else "[!!] "
    print("  " + mark + label + (("  " + extra) if extra else ""))
    if not cond:
        _ok = False


def _log_candidates_from_gate_hook() -> list:
    """取适配层的候选日志路径。

    ⚠️ 候选逻辑**只允许有一份**（在 gate_hook.py 里）——
       两处各写一份必然漂移，而"两处路径不一致"正是本项目踩过的坑
       （verify_live 曾自己抄一份日志路径）。
    ⚠️ 只调用纯计算的 `_log_candidates()`，**不调用** `_pick_log_path()`
       —— 后者会 open 文件做探测（是写操作），预检不该替运行期做决定。
    """
    spec = importlib.util.spec_from_file_location(
        "gh_preflight", os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate_hook.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gh_preflight"] = mod
    spec.loader.exec_module(mod)
    return mod._log_candidates()


def main() -> int:
    print("=" * 92)
    print("DSH 门控 hook · 挂载预检")
    print("=" * 92)

    print("=== 1. 用户配置 cordis.patch.yml ===")
    try:
        cfg = yaml.safe_load(open(CORDS_PATCH, encoding="utf-8"))
    except Exception as exc:                        # noqa: BLE001
        chk("cordis.patch.yml 能解析", False, str(exc))
        return 1
    chk("cordis.patch.yml 能解析", True, f"顶层 {type(cfg).__name__} / {len(cfg)} 个元素")

    entry = None
    for it in cfg:
        for x in (it.get("insert") or []):
            if isinstance(x, dict) and x.get("id") == PLUGIN_ID:
                entry = x
    chk(f"{PLUGIN_ID} 已注册", entry is not None)
    if entry is None:
        return 1
    chk("插件名正确", entry.get("name") == PLUGIN_NAME, str(entry.get("name")))

    print("=== 2. 插件包已安装且已构建 ===")
    chk("入口文件 lib/index.js 存在", os.path.isfile(PLUGIN_ENTRY), PLUGIN_ENTRY)

    print("=== 3. configPath 与 hooks.json ===")
    cp = (entry.get("config") or {}).get("configPath", "")
    chk("configPath 是绝对路径", os.path.isabs(cp), cp)
    chk("configPath 指向的文件存在", os.path.isfile(cp))
    if not os.path.isfile(cp):
        return 1
    try:
        hj = json.load(open(cp, encoding="utf-8"))
    except Exception as exc:                        # noqa: BLE001
        chk("hooks.json 能解析", False, str(exc))
        return 1
    chk("hooks.json 能解析", True)
    groups = (hj.get("hooks") or {}).get("PreToolUse") or []
    chk("有 PreToolUse 配置组", len(groups) > 0, f"{len(groups)} 组")

    print("=== 4. 每组 matcher 与 command ===")
    for g in groups:
        m = str(g.get("matcher", ""))
        # claude 模式：纯 [A-Za-z0-9_|] 视为字面量（| = 精确交替），否则按正则处理
        chk(f'matcher "{m}" 形态合法', bool(re.fullmatch(r"[A-Za-z0-9_|]+", m)))
        for h in g.get("hooks") or []:
            cmd = str(h.get("command", ""))
            chk("  设了 timeout（单位秒）", isinstance(h.get("timeout"), int),
                f"{h.get('timeout')}")
            # ⚠️ 2026-09-27：命令前允许 `&` 调用符 —— PowerShell 要求带引号路径的
            #    命令调用必须写 `& "path"`，否则整个命令被当表达式解析（Unexpected token '-S'）。
            mp = re.match(r"(?:&\s+)?\"([^\"]+)\"", cmd)
            chk("  解释器路径存在", bool(mp) and os.path.isfile(mp.group(1)),
                mp.group(1) if mp else "(未解析出)")
            ms = re.search(r'"([^"]+\.py)"', cmd)
            chk("  脚本路径存在", bool(ms) and os.path.isfile(ms.group(1)),
                os.path.basename(ms.group(1)) if ms else "(未解析出)")

    print()
    print("=== 5. 改完配置后，需要重启 dsh 吗？ ===")
    # ⚠️ 这一项是 2026-09-24 新增的：当时配置每一项都写对了，但跑测试命令**仍然没有弹窗**，
    #    查了很久才想到"根本没重启"。根因是 profile 没配 patchReload=live ⇒ 不会热重载。
    #    ⇒ 这种"少做一步动作"的失败，必须由检查脚本**明说**，不能指望人记得。
    prof_root = os.path.join(DSH_HOME, "profiles")
    live = []
    fixed = []
    if os.path.isdir(prof_root):
        for name in sorted(os.listdir(prof_root)):
            pj = os.path.join(prof_root, name, "package.json")
            if not os.path.isfile(pj):
                continue
            try:
                spec = json.load(open(pj, encoding="utf-8"))
            except Exception:                          # noqa: BLE001
                continue
            mode = ((spec.get("dsh") or {}).get("profile") or {}).get("patchReload")
            (live if mode == "live" else fixed).append((name, mode or "(未设置)"))
    for name, mode in live:
        print(f"  profile {name}: patchReload = {mode}")
    for name, mode in fixed:
        print(f"  profile {name}: patchReload = {mode}")
    if live and not fixed:
        chk("有 profile 是 live ⇒ 可能热重载（但仍建议重启确认）", True)
    else:
        print("  ⇒ 没有 profile 配 patchReload=live ⇒ **改完 cordis.patch.yml 必须重启 dsh**")
        chk("已提醒必须重启（不是故障，是必须做的动作）", True)

    print()
    print("=== 6. 日志落点：候选位置里哪些可写？（这一项会救你一次）===")
    # ⚠️ 为什么必须有这一项（2026-09-24 真实事故）：
    #    宿主（DSH）有文件沙箱（workspace-write），而本目录在它的**工作区之外** ——
    #    连写一个几百字节的基线 json 都被拒。同一个限制当然也会落在**门控自己的日志**上。
    #    而日志写不进去的后果很阴险：**"没有日志"会被读成"门控没生效"**，
    #    于是去改配置（错方向），真正该做的是换个日志路径。
    #
    # ✅ 2026-09-24 已修：适配层不再死盯一个路径，而是**按候选顺序探测、取第一个
    #    能写的**（脚本目录 → cwd=DSH 会话工作区 → 系统临时目录），
    #    全部失败才写 stderr 发声。所以"某个候选不可写"**不是故障**，会自动跳过；
    #    只有"全不可写"才是故障。
    #
    # ⚠️ 但要留意本检查的**局限**：它只在**当前这个环境**里试写。
    #    宿主带的沙箱可能与当前环境不同 ⇒ 这里通过**不代表**在宿主里也通过。
    #    宿主里的判据是：重启后 DSH 控制台里有没有 `[gate-hook] ⚠️ 取证日志…`。
    try:
        log_cands = _log_candidates_from_gate_hook()
    except Exception as exc:                           # noqa: BLE001
        chk("能取到候选列表", False, f"{exc.__class__.__name__}: {exc}")
        log_cands = []
    writable = []
    for cand in log_cands:
        probe = cand + ".writeprobe"
        try:
            with open(probe, "a", encoding="utf-8") as fh:
                fh.write("probe\n")
            os.remove(probe)
            writable.append(cand)
            print(f"  [OK]  可写    {cand}")
        except OSError as exc:
            print(f"  [--]  不可写  {cand}   （{exc.__class__.__name__}）⇒ 会自动跳到下一个")
    chk("至少一个候选可写（仅本环境）", bool(writable),
        f"本环境会选中：{writable[0] if writable else '—'}")
    if writable:
        print("        ⚠️ 局限：这只证明**当前环境**可写。宿主若带沙箱（workspace-write）")
        print("           而脚本目录在工作区外，则宿主里会**自动降级**到 cwd / 临时目录。")
        print("           ⇒ 宿主里的判据：重启后看 DSH 控制台有没有")
        print("             `[gate-hook] ⚠️ 取证日志…`；以及跑 --logstat 看候选清单。")
    else:
        print("        ⇒ **不要为此放宽沙箱**；改用 `--log <允许写的路径>`。")

    print()
    print("=" * 92)
    # ⚠️ 措辞刻意分开"改配置"与"改脚本"两件事：本预检查的是**挂载配置**这一层，
    #    只有这一层改了才需要重启；只改匹配/判定脚本是即时生效的（见 README 第六次事故）。
    print("总判定：" + ("✅ 挂载配置全部通过（改过配置才需重启；只改脚本不用）"
                      if _ok else "❌ 有项目未通过，先修再重启"))
    print("=" * 92)
    return 0 if _ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
