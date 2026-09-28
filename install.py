# -*- coding: utf-8 -*-
"""dsh-safegate 安装器：把模板里的占位符替换成本机真实路径。

为什么要有这个脚本
─────────────────
仓库里的 `dsh_hook/hooks.json.template` 和 `dsh_hook/cordis_insert_block.yml`
故意**不含任何本机路径**（否则一公开就把作者的用户名 / 盘符发布出去了）。
但 hook 配置又必须是绝对路径 —— DSH 不会帮你展开 `~`。

⇒ 所以：模板进仓库，真实路径由本脚本在本机生成。
   生成的 `dsh_hook/hooks.json` 已在 .gitignore 里（每人一份，不该入库）。

用法
────
    python install.py              # 只生成 hooks.json，并打印要贴进 cordis.patch.yml 的块
    python install.py --apply      # 额外把那个块追加进 $DSH_HOME/cordis.patch.yml（会先备份）

可选环境变量
────────────
    SAFEGATE_PYTHON     指定解释器（默认 sys.executable，即你当前用的 python）
    DSH_HOME            DSH 配置目录（默认 ~/.dsh）
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ⚠️ 控制台编码兜底：中文 Windows 控制台默认 cp936(GBK)，能编码汉字但**编码不了 emoji**，
#    而本脚本大量输出 ✅/❌/⚠️。不兜底的话这里会直接抛 UnicodeEncodeError 把安装打断。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                  # noqa: BLE001
        pass

ROOT = Path(__file__).resolve().parent
HOOK_DIR = ROOT / "dsh_hook"
TEMPLATE = HOOK_DIR / "hooks.json.template"
HOOKS_JSON = HOOK_DIR / "hooks.json"
CORDIS_BLOCK = HOOK_DIR / "cordis_insert_block.yml"


def repo_path() -> str:
    """给 DSH 用的仓库绝对路径（正斜杠，避免 YAML/JSON 里的反斜杠转义坑）。"""
    return str(ROOT).replace("\\", "/")


def python_path() -> str:
    """解释器路径。

    ⚠️ 刻意不推荐宿主自带的带版本号解释器（~/.workbuddy/binaries/python/versions/x.y.z/）：
       升级后目录名会变，**变了不报错、只是静默起不来**，极难排查。
       系统 python 路径不含版本号，不会随宿主升级失效。
    """
    return os.environ.get("SAFEGATE_PYTHON") or sys.executable.replace("\\", "/")


def gen_hooks_json() -> None:
    if not TEMPLATE.is_file():
        sys.exit(f"✗ 找不到模板：{TEMPLATE}")
    text = TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("__PYTHON__", python_path()).replace("__REPO__", repo_path())
    HOOKS_JSON.write_text(text, encoding="utf-8")
    print(f"✓ 已生成 {HOOKS_JSON}")
    print(f"    解释器 = {python_path()}")
    print(f"    仓库   = {repo_path()}")


def cordis_block_text() -> str:
    text = CORDIS_BLOCK.read_text(encoding="utf-8")
    return text.replace("__REPO__", repo_path())


def apply_cordis() -> None:
    home = Path(os.path.expanduser("~"))
    dsh_home = Path(os.environ.get("DSH_HOME") or (home / ".dsh"))
    target = dsh_home / "cordis.patch.yml"
    if not dsh_home.is_dir():
        sys.exit(f"✗ DSH 配置目录不存在：{dsh_home}（可用 DSH_HOME 环境变量指定）")
    if target.is_file():
        bak = target.with_suffix(target.suffix + f".bak-pre-safegate-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(target, bak)
        print(f"✓ 已备份原配置 → {bak}")
    with open(target, "a", encoding="utf-8") as f:
        f.write("\n" + cordis_block_text())
    print(f"✓ 已把 insert 块追加到 {target}")
    print("  ⚠️ 改完配置**必须重启 dsh** 才生效（profile 未开 patchReload=live 时不会热重载）。")


def main() -> int:
    gen_hooks_json()
    print()
    print("=== 自测（不依赖 DSH，纯规则层）===")
    # ⚠️ 用列表传参、不拼字符串：拼字符串在含空格/括号的路径上会被 shell 二次解析，
    #    报出来的错（"文件名、目录名或卷标语法不正确"）完全指不到真因。
    rc = subprocess.run([sys.executable, str(HOOK_DIR / "gate_hook.py"), "--selftest"]).returncode
    if rc != 0:
        print("✗ 自测未通过，先别接入 DSH。")
        return 1

    print()
    if "--apply" in sys.argv:
        apply_cordis()
        return 0

    print("=== 下一步：把下面这段追加到 $DSH_HOME/cordis.patch.yml ===")
    print("   （或重跑 `python install.py --apply`，脚本会先备份再追加）")
    print()
    print(cordis_block_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
