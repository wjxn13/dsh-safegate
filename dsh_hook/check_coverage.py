# -*- coding: utf-8 -*-
"""核对：DSH 里所有工具，哪些被 hooks.json 的 matcher 覆盖、哪些没有。

━━ 为什么必须要这个脚本 ━━

2026-09-24 的真实事故：门控挂上后跑测试命令，**没有弹窗**。
查下来是因为 DSH 的 PowerShell 工具注册名是 **`pwsh`**（小写），
而我在 matcher 里写成了 `powershell` —— 一个字之差，
结果**这一类工具完全没有保护**，而且**没有任何报错**。

⇒ 教训：**精确 matcher 是脆弱的** —— 漏一个名字 = 漏一整类工具，且静默。
   所以不能"配完看着对就行"，必须有一道**从安装包反向核对**的检查。

━━ 本脚本回答**两个**事实问题（都必须答）━━

  ① DSH 里到底有哪些工具名？哪些被 matcher 覆盖了？
  ② matcher 命中的那些名字，**适配层（gate_hook.py）是否认识**？

⚠️ 为什么 ② 不能省 —— 2026-09-24 的**第二次**事故：

把 matcher 从 `powershell` 改成正确的 `pwsh` 之后，我做了端到端验证，
发现 `Test-Path`（纯只读）**依然弹窗**。原因是 `gate_hook.py` 的
`TOOL_NAME_MAP` 里也写着 `powershell`，**没跟着改** ⇒
工具名进入不了任何分支 ⇒ 掉进 fail-closed ⇒ **每一次 pwsh 调用都弹窗**。

⇒ 教训：**"matcher 命中" 与 "适配层认识" 是两道独立且都会静默失效的关**。
   只核对其中的一道，另一道错了照样不报错。
   本脚本两道都查，并且用**行为**（跑一次 decide()）而不是**字面**（比 key）来验 ② ——
   因为字面比对查不出"名字对但分支条件写错"这类问题。

━━ 本脚本的立场 ━━

它**不替你判断**哪个工具"该不该门控"（那是策略问题），只核对已配好的东西是否真的通。
对"名字看起来会写/会执行但没配"的，额外标一个 ⚠ 提示人工确认。

用法：`python check_coverage.py`
"""

import importlib.util
import json
import os
import re
import sys

# ⚠️ 控制台编码兜底（模块级，覆盖所有入口）：中文 Windows 控制台默认 cp936(GBK)，
#    能编码汉字但**编码不了 emoji**，而本脚本大量输出 ✅/❌/⚠️。
#    真实事故（2026-09-24）：同类问题在 gate_hook.py 上发生过。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                  # noqa: BLE001
        pass

# ══════════════════════════════════════════════════════════════════════
#  路径：一律**算出来**，不写死用户名 / 机器盘符
# ══════════════════════════════════════════════════════════════════════
#  `_HERE` = 本脚本所在目录（仓库的 dsh_hook/），`_ROOT` = 仓库根目录。
#  ⇒ 这样无论仓库被克隆到哪，覆盖检查都能找到它自己的 hooks.json。
#  `TOOL_ROOT` 指向 DSH 的插件目录，走 DSH_HOME / DSH_NODE_MODULES 环境变量覆盖。
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_HOME = os.path.expanduser("~")
_DSH_HOME = os.environ.get("DSH_HOME") or os.path.join(_HOME, ".dsh")

TOOL_ROOT = os.environ.get("DSH_NODE_MODULES") or os.path.join(_DSH_HOME, "profiles", "node_modules")
TOOL_ROOT = os.path.join(TOOL_ROOT, "@deepseek-ai")
HOOKS_JSON = os.path.join(_HERE, "hooks.json")
GATE_HOOK = os.path.join(_HERE, "gate_hook.py")

# 工具定义对象的特征：`ctx.tools.register(defineTool({` 之后紧跟 `name: "xxx",`
#   ⚠️ 试过两个更弱的判据，都不行：
#      · "后 5 行内出现 description" ⇒ 从 `dsh-tool-cordis` 提出 100+ 个假的
#        （那是插件配置 schema 的字段名：access / active / actor / adapter …）；
#      · "紧邻下一行是 description" ⇒ 字段级描述也会命中，仍有噪声。
#   最终用**前置锚点** `defineTool(`：schema 字段前面永远不会有它。
_NAME_RE = re.compile(r'name:\s*"([a-z_][a-z0-9_]*)"')
_ANCHOR = "defineTool"

# 名字里含这些词 ⇒ "看起来会写会执行"，值得人工确认是否该门控（启发式，不是结论）
_SUSPICIOUS = re.compile(
    r"bash|pwsh|shell|exec|run|write|edit|replace|delete|remove|move|copy|"
    r"create|kill|send|install|upload|patch",
    re.IGNORECASE,
)


def extract_tools():
    """从已安装的工具包里提取 (工具名, 来源包)。"""
    found = {}
    for pkg in sorted(os.listdir(TOOL_ROOT)):
        if not pkg.startswith("dsh-tool-"):
            continue
        idx = os.path.join(TOOL_ROOT, pkg, "lib", "index.js")
        if not os.path.isfile(idx):
            continue
        try:
            lines = open(idx, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            m = _NAME_RE.search(line)
            if not m:
                continue
            # 只看"工具定义"：前面几行必须有 `defineTool(` 锚点
            if _ANCHOR not in "\n".join(lines[max(0, i - 4):i]):
                continue
            found.setdefault(m.group(1), pkg)
    return found


def load_matchers():
    hj = json.load(open(HOOKS_JSON, encoding="utf-8"))
    patterns = []
    names = []
    for g in (hj.get("hooks") or {}).get("PreToolUse") or []:
        pat = str(g.get("matcher", ""))
        if pat not in patterns:
            patterns.append(pat)
        # claude 模式：纯 [A-Za-z0-9_|] 视为字面量交替；`*`/空 = 全匹配
        if pat in ("", "*"):
            names.append("*")
        else:
            for name in pat.split("|"):
                if name.strip() and name.strip() not in names:
                    names.append(name.strip())
    return names, patterns


# ── ② 适配层是否认识这些名字：用**行为**验证，不比对字面 ──
# 喂一个"良性只读参数包"，如果仍返回通用的 fail-closed 理由，
# 就说明这个名字没进任何分支 ⇒ 每次调用都会弹窗。
GENERIC_FAILCLOSED = "不在规则表内"
_BENIGN_ARGS = {
    "command": "ls -la",
    "file_path": "D:/proj/some_file.txt",
    "path": "D:/proj/some_file.txt",
    "old_str": "a", "new_str": "b", "content": "x",
}


def load_gate_hook():
    spec = importlib.util.spec_from_file_location("gate_hook_check", GATE_HOOK)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gate_hook_check"] = mod
    spec.loader.exec_module(mod)
    return mod


def check_adapter(covered_names, gh):
    """返回 (认识的名字列表, 不认识的名字列表)。"""
    known, unknown = [], []
    for name in covered_names:
        if name == "*":
            continue
        try:
            _dec, why = gh.decide({"tool_name": name, "tool_input": dict(_BENIGN_ARGS)})
        except Exception as exc:                       # noqa: BLE001
            unknown.append((name, f"decide() 抛异常：{exc}"))
            continue
        if GENERIC_FAILCLOSED in why:
            unknown.append((name, why))
        else:
            known.append(name)
    return known, unknown


def _negctl() -> int:
    """负对照：证明第 ② 关**确实会失败**。

    ⚠️ 为什么必须做这个：一个"永远通过"的检查等于没有检查。
       而我恰恰是因为在**上一轮**把一个永远通过的印象当成了验证，
       才让 `powershell` → `pwsh` 的映射缺口溜过去、导致每条命令都弹窗。
       ⇒ 所以这里故意把适配层改坏，确认核对脚本会报 FAIL。

    做法：临时把 `pwsh` 从 TOOL_NAME_MAP 里摘掉（复刻真实事故），看第 ② 关是否报警。
    摘掉后立刻还原，不落盘。
    """
    print("=" * 96)
    print("负对照：故意把适配层改坏，确认第 ② 关会报 FAIL（检验这个检查本身有没有判别力）")
    print("=" * 96)
    gh = load_gate_hook()
    probe = ["bash", "pwsh", "edit", "write", "str_replace_editor", "cordis_run"]

    _k, u = check_adapter(probe, gh)
    baseline = [n for n, _ in u]

    saved = gh.TOOL_NAME_MAP.pop("pwsh", None)
    _k2, u2 = check_adapter(["pwsh"], gh)
    broken = [n for n, _ in u2]
    if saved is not None:
        gh.TOOL_NAME_MAP["pwsh"] = saved

    print(f"  对照组 A（原样）            不认识的名字：{baseline or '无'}")
    print(f"  对照组 B（摘掉 pwsh 映射）   不认识的名字：{broken or '无'}")

    ok = (not baseline) and (broken == ["pwsh"])
    print("-" * 96)
    if ok:
        print("  ✅ 负对照通过：原样时全认识；一旦摘掉映射就立刻报 FAIL ⇒ 第 ② 关有判别力。")
        return 0
    print("  ❌ 负对照失败：这个检查没有判别力，不能作为验证依据。")
    return 1


def main() -> int:
    if "--negctl" in sys.argv:
        return _negctl()

    tools = extract_tools()
    covered_names, patterns = load_matchers()

    print("=" * 96)
    print(f"DSH 工具名 × 门控覆盖核对（从 {TOOL_ROOT} 的安装产物提取，共 {len(tools)} 个工具名）")
    print("=" * 96)
    print(f"  当前 matcher: {patterns}")
    print()

    covered = []
    uncovered = []
    for name, pkg in sorted(tools.items()):
        hit = (name in covered_names) or ("*" in covered_names)
        (covered if hit else uncovered).append((name, pkg))

    print(f"✅ 已被 matcher 覆盖（{len(covered)} 个）：")
    for name, pkg in covered:
        print(f"     {name:24} ← {pkg}")

    print()
    print(f"○ 未被覆盖（{len(uncovered)} 个）：")
    risky = []
    for name, pkg in uncovered:
        flag = "⚠ 名字像会写/会执行，请人工确认是否需要门控" if _SUSPICIOUS.search(name) else ""
        if flag:
            risky.append(name)
        print(f"     {name:24} ← {pkg:34} {flag}")

    # ── 第二关：matcher 命中的名字，适配层认识吗 ──
    print()
    print("=" * 96)
    print("第 ② 关：matcher 命中的名字，适配层（gate_hook.py）认识吗？")
    print("=" * 96)
    try:
        gh = load_gate_hook()
    except Exception as exc:                           # noqa: BLE001
        print(f"  ❌ 无法加载 gate_hook.py：{exc}")
        return 2
    known, unknown = check_adapter(covered_names, gh)
    for name in known:
        mapped = gh.TOOL_NAME_MAP.get(name, name)
        extra = f" → {mapped}" if mapped != name else "（原名进分支）"
        print(f"     [OK]   {name:24}{extra}")
    for name, why in unknown:
        print(f"     [FAIL] {name:24} 每次调用都会掉进 fail-closed：{why[:60]}")

    print()
    print("=" * 96)
    # ⚠️ 退出码语义（踩过坑）：只有**硬缺口**才算失败。
    #    "哪些未覆盖工具该加进 matcher" 是**策略问题，要人来定**，
    #    它永远非空 ⇒ 若也算失败，这脚本就永远退出 1，
    #    跟"永远退出 0"一样没用（一个永远失败的检查等于没有检查）。
    #    要把它当失败看：加 --strict。
    strict = "--strict" in sys.argv
    hard_fail = bool(unknown)

    if unknown:
        print(f"❌ 【硬缺口】有 {len(unknown)} 个**已被 matcher 命中但适配层不认识**的名字：")
        print(f"   {[n for n, _ in unknown]}")
        print("   ⇒ 后果：这些工具**每一次调用都会弹窗**（包括只读操作）。")
        print("   ⇒ 修法：在 gate_hook.py 的 TOOL_NAME_MAP 里补上，或加专门分支。")
    else:
        print("✅ 第 ② 关通过：matcher 命中的名字，适配层全都认识。")

    if risky:
        print()
        print(f"⚠️  【提示·非失败】有 {len(risky)} 个未覆盖工具的名字带'写/执行'语义：{risky}")
        print("   ⇒ 这是**等你拍板**的问题，不是故障：它会不会改文件 / 执行命令？"
              "会的话就加进 matcher。")

    print()
    if hard_fail:
        print("❌ 存在硬缺口（matcher 与适配层不一致）—— 必须修。")
    elif risky:
        print("✅ 无硬缺口。上面那条 ⚠️ 是策略待定项，不阻塞。")
    else:
        print("✅ 两关全过：没有'名不副实'的静默缺口。")
    print("=" * 96)
    if hard_fail:
        return 1
    if strict and risky:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
