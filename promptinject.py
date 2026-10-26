"""promptinject —— 检查提示词里有没有藏着的指令注入。

设计原则：
1. **区分「在讲注入」和「真的在注入」**。教程里出现的注入样例不是注入。
2. **按位置和结构判定**，不只靠关键词。关键词一撞就报，报告立刻没人信。
3. **只检测不防护**。它不重写内容，也不承诺万无一失——防御是另一件事。

仅依赖 Python 标准库。

用法:
    python promptinject.py --help
    python promptinject.py --file content.md
    python promptinject.py --file content.md --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# ---------------------------------------------------------------------------
# 注入模式
# ---------------------------------------------------------------------------

# 指令式句子的结构特征：祈使句 + 第二人称 + 动作动词
IMPERATIVE_VERBS = (
    "ignore", "disregard", "forget", "override", "bypass", "skip",
    "reveal", "print", "output", "show", "display", "execute", "run",
    "call", "send", "email", "post", "delete", "remove", "update",
    "modify", "set", "use", "act", "answer", "respond", "reply",
    "say", "write", "tell", "give", "provide", "list", "return",
)

IMPERATIVE_VERBS_CN = (
    "忽略", "无视", "不要理会", "忘记", "覆盖", "绕过", "跳过",
    "输出", "打印", "显示", "展示", "告诉", "请务必", "务必", "必须执行",
    "运行", "执行", "调用", "发送", "邮寄", "删除", "移除", "上传",
    "修改", "设置", "扮演", "回答", "回复", "返回", "列出", "写",
)

# 指令式句子的句首
IMPERATIVE_START = re.compile(
    r"^\s*(?:ignore|disregard|forget|override|bypass|skip|reveal|print|"
    r"output|show|display|execute|run|call|send|delete|remove|update|"
    r"modify|set|act|answer|respond|say|write|tell|provide|list|return|"
    r"you must|you should|your new|new instruction|system:)",
    re.I)

IMPERATIVE_START_CN = re.compile(
    r"^\s*(?:忽略|无视|忘记|覆盖|绕过|跳过|输出|打印|显示|告诉|"
    r"务必|运行|执行|调用|发送|删除|移除|上传|修改|设置|扮演|"
    r"回答|回复|返回|列出|写|你的新|新指令|系统[:：])")

# 第二人称代词：出现在句子里说明是对模型说的
SECOND_PERSON = re.compile(
    r"\b(you|your|yours|yourself)\b", re.I)

SECOND_PERSON_CN = re.compile(r"(你|你的|您|你们)")

# 越权类词汇
OVERRIDE_WORDS = re.compile(
    r"\b(ignore|disregard|override|bypass|forget|previous|above|"
    r"earlier|system\s+prompt|instructions?)\b", re.I)

OVERRIDE_WORDS_CN = re.compile(
    r"(忽略|无视|覆盖|绕过|前面的|之前的|上述|系统提示|系统指令|指令)")

# 敏感目标：模型可能被诱去吐出的东西
SENSITIVE_TARGET = re.compile(
    r"\b(api[_ ]?key|secret|password|token|credential|system prompt|"
    r"prompt|instruction|key|configuration|\.env)\b", re.I)

SENSITIVE_TARGET_CN = re.compile(
    r"(密钥|密码|令牌|凭证|系统提示|提示词|指令|配置|环境变量)")

# 引用/示例语境：这里的「指令」是引用，不是执行
QUOTING_CONTEXT = re.compile(
    r"(示例|例如下|比如|教程|教学|测试用例|演示|示范|攻击样例|"
    r"防范|防御|如何防范|不要这样|反面例子|反例|伪例)", re.I)

CODE_BLOCK_RE = re.compile(r"^\s*(?:```|~~~)")


def split_lines(text: str) -> list[dict]:
    """按行切，标记是否在代码块内。"""
    out: list[dict] = []
    in_fence = False
    for i, raw in enumerate(text.splitlines()):
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            in_fence = not in_fence
            out.append({"index": i, "text": line, "in_code": in_fence})
            continue
        out.append({"index": i, "text": line, "in_code": in_fence})
    return out


def is_injection(line: str, context: str) -> dict:
    """判断一行是不是指令注入。返回判定明细。"""
    text = line.strip()
    if not text:
        return {"is_injection": False, "reasons": []}

    reasons: list[str] = []
    score = 0.0

    imperative = bool(IMPERATIVE_START.match(text) or IMPERATIVE_START_CN.match(text))
    has_verb = any(v in text.lower() for v in IMPERATIVE_VERBS)
    has_verb = has_verb or any(v in text for v in IMPERATIVE_VERBS_CN)

    second_person = bool(SECOND_PERSON.search(text) or SECOND_PERSON_CN.search(text))
    override = bool(OVERRIDE_WORDS.search(text) or OVERRIDE_WORDS_CN.search(text))
    sensitive = bool(SENSITIVE_TARGET.search(text) or SENSITIVE_TARGET_CN.search(text))

    if imperative:
        reasons.append("祈使句开头")
        score += 0.35
    if has_verb:
        reasons.append("含动作动词")
        score += 0.2
    if second_person:
        reasons.append("含第二人称")
        score += 0.2
    if override:
        reasons.append("含覆盖/忽略类词")
        score += 0.35
    if sensitive:
        reasons.append("指向敏感目标")
        score += 0.3

    quoting = bool(QUOTING_CONTEXT.search(context or ""))

    if quoting:
        reasons.append("所在段落像是在讲这件事（引用语境）")
        score -= 0.6

    score = max(0.0, min(1.0, score))
    threshold = 0.6

    return {
        "is_injection": score >= threshold and not quoting,
        "score": round(score, 2),
        "reasons": reasons,
        "signals": {
            "imperative": imperative,
            "action_verb": has_verb,
            "second_person": second_person,
            "override": override,
            "sensitive_target": sensitive,
        },
        "in_quoting_context": quoting,
    }


def scan(text: str) -> dict:
    """扫描一段内容。"""
    lines = split_lines(text)
    findings: list[dict] = []

    for i, line in enumerate(lines):
        if not line["text"].strip():
            continue
        if line["in_code"]:
            # 代码块内单独判断（代码块本身是常见的安全承载方式）
            continue

        # 上下文：前后各两行
        lo = max(0, i - 2)
        hi = min(len(lines), i + 3)
        context = "\n".join(l["text"] for l in lines[lo:hi]
                            if not l["in_code"])

        verdict = is_injection(line["text"], context)
        if verdict["is_injection"]:
            findings.append({
                "line": line["index"] + 1,
                "text": line["text"].strip(),
                **verdict,
            })

    # 代码块内也要看一眼：代码块里塞指令也是一种手法
    code_findings: list[dict] = []
    for i, line in enumerate(lines):
        if not line["in_code"] or not line["text"].strip():
            continue
        verdict = is_injection(line["text"], "")
        if verdict["score"] >= 0.6:
            code_findings.append({
                "line": line["index"] + 1,
                "text": line["text"].strip(),
                "in_code": True,
                **verdict,
            })

    return {
        "line_count": len(lines),
        "findings": findings,
        "code_findings": code_findings,
        "summary": {
            "injection_count": len(findings),
            "code_injection_count": len(code_findings),
            "total": len(findings) + len(code_findings),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def render(result: dict) -> str:
    out: list[str] = []
    s = result["summary"]
    out.append("指令注入检查")
    out.append("=" * 60)
    out.append(f"扫描 {result['line_count']} 行 ｜ "
               f"正文命中 {s['injection_count']} ｜ 代码块命中 {s['code_injection_count']}")
    out.append("")

    if not result["findings"] and not result["code_findings"]:
        out.append("未发现疑似指令注入。")
        out.append("")
        out.append("注意：这不是「安全」的证明。改个说法就可能绕过基于结构的检测。")
        return "\n".join(out)

    for f in result["findings"]:
        out.append(f"第 {f['line']} 行　置信度 {f['score']:.2f}")
        out.append(f"  {f['text']}")
        out.append(f"  依据：{'、'.join(f['reasons'])}")
        out.append("")

    if result["code_findings"]:
        out.append("代码块内：")
        for f in result["code_findings"]:
            out.append(f"  第 {f['line']} 行　置信度 {f['score']:.2f}")
            out.append(f"    {f['text']}")
            out.append(f"    依据：{'、'.join(f['reasons'])}")
        out.append("")

    out.append("注：这是启发式检测，会有漏报与误报。"
               "把命中项当线索去人工确认，不要直接当结论。")
    return "\n".join(out).rstrip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="promptinject",
        description="检查提示词里有没有藏着的指令注入（仅依赖标准库）",
        epilog=(
            "示例：\n"
            "  python promptinject.py --file content.md\n"
            "  python promptinject.py --file content.md --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--file", required=True, help="要检查的内容文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print(f"读不了文件：{e}", file=sys.stderr)
        return 2

    if not text.strip():
        print("文件是空的。", file=sys.stderr)
        return 2

    result = scan(text)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(render(result))
    return 1 if result["summary"]["total"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
