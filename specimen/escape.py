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


_TLD_DOT = re.compile(r"(?<=[A-Za-z0-9-])\.(?=(?:[A-Za-z]{2,24})(?:[/:\s'\"`)\],;]|$))")
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w.])")
_SAFE_EXT = {"exe", "dll", "sys", "bat", "cmd", "com", "scr", "ps1", "vbs", "js", "tmp", "dat", "txt", "log",
             "ini", "lnk", "db", "xml", "json", "bin", "jpg", "png", "zip", "msi", "inf", "cpl", "ocx", "drv",
             "php", "html", "htm", "asp", "aspx", "jsp", "cgi", "url", "vbe", "wsf", "hta", "mui", "nls", "manifest"}


# dotted IPv4 with hex (0x..) or octal (0..) parts, e.g. 0xC0.0xA8.1.1 or 0300.0250.1.1
_IPV4_ALT = re.compile(r"(?i)(?<![\w.])((?:0x[0-9a-f]{1,8}|0[0-7]{1,11}|\d{1,10})(?:\.(?:0x[0-9a-f]{1,8}|0[0-7]{1,11}|"
                       r"\d{1,10})){1,3})(?![\w.])")
# protocol-relative or scheme URL host: //example.com, //3232235777 (integer IPv4), //0xc0a80101
_HOST_SLASHES = re.compile(r"(?i)(?<![\w/:])(//)(?=(?:[\w-]+\.)+[\w-]+|\d{6,10}\b|0x[0-9a-f]{6,8}\b|\[)")
_SCHEME = re.compile(r"(?i)\b(https?|ftps?|wss?|file|smb)://")


def defang(s: str) -> str:
    """Defang URLs, domains and IPv4 addresses for human-facing text.

    Handles ``http(s)``/``ftp``/``ws``/``file``/``smb`` schemes,
    protocol-relative ``//host`` URLs, dotted IPv4 (also with hex or octal
    parts) and integer IPv4 hosts after ``//``. File names such as
    ``kernel32.dll`` are left alone (common file extensions are not treated
    as top-level domains)."""
    def scheme(m: re.Match[str]) -> str:
        sch = m.group(1).lower()
        if sch.startswith("http"):
            return "hxxp" + sch[4:] + "://"
        if sch.startswith("ftp"):
            return "fxp" + sch[3:] + "://"
        return sch + "[:]//"
    s = _SCHEME.sub(scheme, s)
    s = _HOST_SLASHES.sub("[//]", s)

    def dot(m: re.Match[str]) -> str:
        tail = re.match(r"[A-Za-z]+", s[m.end():])
        return "." if tail and tail.group().lower() in _SAFE_EXT else "[.]"
    s = _IPV4.sub(lambda m: "[.]".join(m.groups()), s)
    s = _IPV4_ALT.sub(lambda m: m.group(1).replace(".", "[.]")
                      if re.search(r"(?i)0x|(^|\.)0\d", m.group(1)) else m.group(1), s)
    return _TLD_DOT.sub(dot, s)


# Markdown structure characters that untrusted text must never contribute:
# links/images ([ ] ( ) !), escapes (\), emphasis (* _), code (`), tables (|).
_MD_ENTITIES = {"\\": "&#92;", "[": "&#91;", "]": "&#93;", "(": "&#40;", ")": "&#41;", "!": "&#33;",
                "|": "&#124;", "`": "&#96;", "*": "&#42;", "_": "&#95;", "#": "&#35;", "~": "&#126;"}
_MD_SPECIAL = re.compile("[" + re.escape("".join(_MD_ENTITIES)) + "]")


def md_text(s: object, defang_iocs: bool = True) -> str:
    """Untrusted text for a Markdown table cell or list item.

    HTML-escaped, single-line; every Markdown-structural character
    (``[ ] ( ) ! \\ | ` * _ # ~``) becomes an HTML entity, so report data can
    never form a link, image, code span, emphasis or table cell; the
    pymdown snippet marker ``--8<--`` is broken; network IOCs are defanged."""
    t = _CTRL.sub(" ", str(s))
    if defang_iocs:  # defang first: its "[.]" markers are then entity-encoded like everything else
        t = defang(t)
    t = html.escape(t, quote=False)
    t = _MD_SPECIAL.sub(lambda m: _MD_ENTITIES[m.group()], t)
    return t.replace("--8&lt;--", "-&#45;8&lt;--")


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
