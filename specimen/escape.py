r"""Escaping for untrusted report strings in emitted rules and Markdown.

Every value that reaches a Sigma rule, a YARA rule, a Mermaid label or a
Markdown report comes from a sandbox report, i.e. from the sample under
analysis. These helpers keep such strings from changing the structure of
the output (rule injection, broken YAML, HTML or snippet injection).
"""
from __future__ import annotations

import html
import re

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
BS = "\\"


def sigma_value(pattern: str) -> str:
    r"""Render an internal wildcard pattern (``*`` = any run) as a Sigma value.

    Literal segments are escaped with Sigma's rules (``\`` becomes ``\\``,
    ``?`` becomes ``\?``), segments are joined by an *unescaped* ``*``, and
    control characters become the single-character wildcard ``?``.

    :param pattern: wildcard pattern as used by the internal matcher.
    :returns: the value to place inside a single-quoted YAML scalar (not yet quoted).
    """
    def lit(seg: str) -> str:
        seg = seg.replace(BS, BS + BS).replace("?", BS + "?")
        return _CTRL.sub("?", seg)
    return "*".join(lit(s) for s in pattern.split("*"))


def sigma_literal(value: str) -> str:
    """Escape a value that must match literally (no wildcards) in Sigma."""
    v = value.replace(BS, BS + BS).replace("*", BS + "*").replace("?", BS + "?")
    return _CTRL.sub("?", v)


def yaml_sq(s: str) -> str:
    """Single-quoted YAML scalar with no control characters."""
    return "'" + _CTRL.sub(" ", s).replace("'", "''") + "'"


def yara_str(s: str) -> str:
    r"""Body of a double-quoted YARA text string (``\``, ``"`` and non-printables escaped)."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == BS:
            out.append(BS + BS)
        elif ch == '"':
            out.append(BS + '"')
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        else:
            out.append("".join(f"{BS}x{b:02x}" for b in ch.encode("utf-8")))
    return "".join(out)


def hex_or(s: str, n: int, fallback: str = "") -> str:
    """``s`` lower-cased if it is ``n`` hex digits (32 or 64), else ``fallback``."""
    s = (s or "").strip().lower()
    return s if (_HEX32 if n == 32 else _HEX64).match(s) else fallback


_TLD_DOT = re.compile(r"(?<=[A-Za-z0-9-])\.(?=(?:[A-Za-z]{2,24}|\d{1,3})(?:[/:\s'\"`)\],;]|$))")
_SAFE_EXT = {"exe", "dll", "sys", "bat", "cmd", "com", "scr", "ps1", "vbs", "js", "tmp", "dat", "txt", "log",
             "ini", "lnk", "db", "xml", "json", "bin", "jpg", "png", "zip", "msi", "inf", "cpl", "ocx", "drv",
             "php", "html", "htm", "asp", "aspx", "jsp", "cgi", "url", "vbe", "wsf", "hta", "mui", "nls", "manifest"}


def defang(s: str) -> str:
    """Defang URLs, domains and IPv4 addresses for human-facing text.

    File names such as ``kernel32.dll`` are left alone (common file
    extensions are not treated as top-level domains)."""
    s = re.sub(r"(?i)\bhttp(s?)://", r"hxxp\1://", s)

    def dot(m: re.Match[str]) -> str:
        tail = re.match(r"[A-Za-z]+", s[m.end():])
        return "." if tail and tail.group().lower() in _SAFE_EXT else "[.]"
    return _TLD_DOT.sub(dot, s)


def md_text(s: object, defang_iocs: bool = True) -> str:
    """Untrusted text for a Markdown table cell or list item.

    HTML-escaped, single-line, pipes and backticks neutralised, the
    pymdown snippet marker ``--8<--`` broken, network IOCs defanged."""
    t = _CTRL.sub(" ", str(s))
    t = html.escape(t, quote=False).replace("|", "&#124;").replace("`", "&#96;").replace("*", "&#42;")
    t = t.replace("_", "&#95;").replace("--8&lt;--", "-&#45;8&lt;--")
    return defang(t) if defang_iocs else t


def mermaid_label(s: str, n: int = 60) -> str:
    """Mermaid node label: quotes/brackets/HTML neutralised, shortened in the middle."""
    t = _CTRL.sub(" ", s)
    if len(t) > n:
        k = (n - 1) // 2
        t = t[:k] + "~" + t[-(n - 1 - k):]
    for a, b in (('"', "'"), ("<", "("), (">", ")"), ("[", "("), ("]", ")"), ("{", "("), ("}", ")"),
                 ("|", "/"), ("`", "'"), ("#", "")):
        t = t.replace(a, b)
    return defang(t)
