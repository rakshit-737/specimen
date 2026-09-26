"""Specificity-constrained detection synthesis (Sigma + YARA), v2.

The MVP synthesizer (``synth.py``) emits exact-value rules only for events
that map to an ATT&CK technique. On real sandbox data that produces rules
that almost never fire on a sibling sample: dropped-file names, registry
values and command lines are randomised per run.

This module instead:

1. extracts *candidate selections* from every host-visible action of one
   run (process creation, registry write, file write),
2. builds a ladder of increasingly general wildcard patterns for each one
   (exact -> numbers/hex wildcarded -> file stem wildcarded -> parent dir
   wildcarded),
3. keeps the **most general rung that still has zero hits on a negative
   corpus** (benign traces and/or other families) and still carries enough
   literal characters to be meaningful.

Matching uses the same line format for rules and traces, so a rule is one
compiled regex searched over a per-category text blob - fast enough to
validate against thousands of traces.

Standard library only.
"""
from __future__ import annotations

import ntpath
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

# Sigma logsource categories and the field each line represents
CATEGORIES = {
    "process_creation": ("Image", "CommandLine"),
    "registry_set": ("TargetObject",),
    "file_event": ("TargetFilename",),
}
EVENT_CATEGORY = {"process_create": "process_creation", "registry_set": "registry_set",
                  "file_write": "file_event"}
MIN_LITERAL = 10
MAX_RULES = 10

_USER = re.compile(r"(?i)(c:\\users\\)[^\\]+")
_SID = re.compile(r"(?i)s-1-5-21(-\d+)+")
_GUID = re.compile(r"(?i)\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_HEXNUM = re.compile(r"(?i)(?<![a-z])(?=[0-9a-f]*\d)[0-9a-f]{4,}(?![a-z])|\d+")
_STARS = re.compile(r"\*{2,}")
_GENERIC_PREFIX = re.compile(r"(?i)^(\*\\)?(c:\\users\\\*\\appdata\\(local|roaming)(\\temp)?|c:\\users\\\*|"
                             r"c:\\windows(\\(system32|syswow64))?|c:\\programdata|hk(ey_)?(current_user|"
                             r"local_machine|lm|cu)\\software(\\microsoft\\windows\\currentversion)?|"
                             r"hkey_users\\\*\\software)")


def image_of(cmdline: str, target: str) -> str:
    """Full image path from a command line (falls back to the target)."""
    c = (cmdline or "").strip()
    if c.startswith('"'):
        end = c.find('"', 1)
        if end > 1:
            return c[1:end]
    m = re.match(r"(?i)^(\S+?\.(exe|com|scr|bat|cmd))\b", c)
    return m.group(1) if m else (target or "")


def event_line(etype: str, target: str, cmdline: str = "") -> tuple[str, str] | None:
    """(category, line) for one event, in the format rules are matched against."""
    cat = EVENT_CATEGORY.get(etype)
    if cat is None:
        return None
    if cat == "process_creation":
        return cat, f"{image_of(cmdline, target)}\t{cmdline or target}"
    return cat, target or ""


def blobs(events: Iterable[Sequence[str]]) -> dict[str, str]:
    """Per-category newline-joined lines for fast rule matching."""
    out: dict[str, list[str]] = {c: [] for c in CATEGORIES}
    for e in events:
        r = event_line(e[0], e[1], e[2] if len(e) > 2 else "")
        if r and r[1]:
            out[r[0]].append(r[1].replace("\n", " "))
    return {c: "\n".join(v) for c, v in out.items()}


# ---------------------------------------------------------------------------
# generalisation ladder
# ---------------------------------------------------------------------------

def _base(v: str) -> str:
    v = _USER.sub(r"\1*", v)
    v = _SID.sub("*", v)
    return _GUID.sub("*", v)


def _tidy(v: str) -> str:
    return _STARS.sub("*", v)


def ladder(value: str, kind: str) -> list[str]:
    """Increasingly general wildcard patterns for one value (most specific first)."""
    v0 = _tidy(_base(value.strip()))
    v1 = _tidy(_HEXNUM.sub("*", v0))
    rungs = [v0, v1]
    if kind in ("path", "image"):
        d, b = ntpath.split(v1)
        ext = b.rsplit(".", 1)[1] if "." in b else ""
        if d:
            rungs.append(_tidy(f"{d}\\*.{ext}" if ext else f"{d}\\*"))
            pd = ntpath.dirname(d)
            if pd:
                rungs.append(_tidy(f"{pd}\\*\\{b}"))
                rungs.append(_tidy(f"{pd}\\*\\*.{ext}" if ext else f"{pd}\\*\\*"))
    elif kind == "key":
        d = ntpath.dirname(v1)
        if d:
            rungs.append(_tidy(d + "\\*"))
    out: list[str] = []
    for r in rungs:
        if r not in out:
            out.append(r)
    return out


def literal_len(pattern: str) -> int:
    """Literal characters left after removing wildcards and generic prefixes."""
    p = _GENERIC_PREFIX.sub("", pattern)
    return len(p.replace("*", "").replace("\\", "").replace(".", ""))


@lru_cache(maxsize=65536)
def to_regex(pattern: str) -> re.Pattern[str]:
    body = ".*".join(re.escape(part) for part in pattern.split("*"))
    return re.compile(rf"(?im)^{body}$")


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SigmaRule:
    category: str
    fields: tuple[tuple[str, str], ...]     # (field, wildcard pattern)
    rung: int = 0
    source: str = ""

    @property
    def line_pattern(self) -> str:
        d = dict(self.fields)
        if self.category == "process_creation":
            return f"{d.get('Image', '*')}\t{d.get('CommandLine', '*')}"
        return next(iter(d.values()))

    def matches(self, blob: dict[str, str]) -> bool:
        text = blob.get(self.category, "")
        return bool(text) and to_regex(self.line_pattern).search(text) is not None

    def to_sigma(self, sha256: str, title: str | None = None, technique: str | None = None) -> str:
        sel = "\n".join(f"        {f}: '{p}'" for f, p in self.fields)
        tags = f"tags:\n    - attack.{technique.lower()}\n" if technique else ""
        return (f"title: {title or 'SPECIMEN auto - ' + self.category + ' pattern'}\n"
                f"status: experimental\n"
                f"description: Auto-synthesized from one sandbox run of {sha256[:16]}; generalisation rung "
                f"{self.rung}; zero hits on the negative corpus at synthesis time. Review before deploy.\n"
                f"author: SPECIMEN\n{tags}logsource:\n    product: windows\n    category: {self.category}\n"
                f"detection:\n    selection:\n{sel}\n    condition: selection\nlevel: medium\n")


def candidates(events: Iterable[Sequence[str]]) -> list[list[SigmaRule]]:
    """One ladder of candidate rules per distinct host-visible action."""
    seen: set[tuple[str, str]] = set()
    out: list[list[SigmaRule]] = []
    for e in events:
        etype, target = e[0], e[1]
        cmd = e[2] if len(e) > 2 else ""
        cat = EVENT_CATEGORY.get(etype)
        if not cat or not (target or cmd):
            continue
        key = (cat, (cmd or target).lower())
        if key in seen:
            continue
        seen.add(key)
        if cat == "process_creation":
            img = image_of(cmd, target)
            lad = [SigmaRule(cat, (("Image", p),), i, cmd) for i, p in enumerate(ladder(img, "image"))]
            args = cmd[len(img) + 2:].strip() if cmd.startswith('"') else cmd[len(img):].strip()
            if args:
                a = _tidy(_HEXNUM.sub("*", _base(args)))
                img_l = ladder(img, "image")
                lad.insert(0, SigmaRule(cat, (("Image", img_l[min(1, len(img_l) - 1)]), ("CommandLine", _tidy(f"*{a}*"))), 0, cmd))
        elif cat == "registry_set":
            lad = [SigmaRule(cat, (("TargetObject", p),), i, target) for i, p in enumerate(ladder(target, "key"))]
        else:
            lad = [SigmaRule(cat, (("TargetFilename", p),), i, target) for i, p in enumerate(ladder(target, "path"))]
        out.append(lad)
    return out


def _literal_ok(rule: SigmaRule) -> bool:
    return all(literal_len(p) >= MIN_LITERAL for f, p in rule.fields if f != "CommandLine") \
        or any(f == "CommandLine" and literal_len(p) >= MIN_LITERAL for f, p in rule.fields)


@dataclass
class SynthesisResult:
    rules: list[SigmaRule] = field(default_factory=list)
    rejected_nonspecific: int = 0
    candidates: int = 0


def synthesize_sigma(events: Iterable[Sequence[str]], negatives: Sequence[dict[str, str]],
                     max_rules: int = MAX_RULES, max_neg_hits: int = 0) -> SynthesisResult:
    """Pick, per candidate action, the most general rung with <= ``max_neg_hits``
    matches in ``negatives`` (per-category blobs of negative traces)."""
    res = SynthesisResult()
    chosen: dict[str, SigmaRule] = {}
    for lad in candidates(events):
        res.candidates += 1
        best = None
        for rule in lad:  # rungs are not strictly nested, so test each one
            if not _literal_ok(rule):
                continue
            hits = 0
            for nb in negatives:
                if rule.matches(nb):
                    hits += 1
                    if hits > max_neg_hits:
                        break
            if hits <= max_neg_hits:
                best = rule  # later rungs are more general: keep the last that passes
        if best is None:
            res.rejected_nonspecific += 1
            continue
        chosen.setdefault(best.line_pattern.lower(), best)
    # prefer general rules (they are the ones that generalise to siblings)
    res.rules = sorted(chosen.values(), key=lambda r: (-r.rung, r.category))[:max_rules]
    return res


# ---------------------------------------------------------------------------
# YARA from static PE metadata (CAPE static.pe)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class YaraPeRule:
    imphash: str
    imports: tuple[tuple[str, str], ...]   # (dll, function)
    need: int

    def matches(self, static_tokens: set[str]) -> bool:
        if self.imphash and f"imphash:{self.imphash}" in static_tokens:
            return True
        if not self.imports:
            return False
        return sum(f"imp:{d}:{f}" in static_tokens for d, f in self.imports) >= self.need

    def to_yara(self, name: str, sha256: str, case: dict[str, str] | None = None) -> str:
        """``case`` maps lower-cased import names back to their original
        spelling (YARA matches function names case-sensitively)."""
        case = case or {}
        conds = []
        if self.imphash:
            conds.append(f'pe.imphash() == "{self.imphash}"')
        if self.imports:
            s = " +\n            ".join(f'pe.imports("{d}", "{case.get(f, f)}")' for d, f in self.imports)
            conds.append(f"(\n            {s}\n        ) >= {self.need}")
        return (f'import "pe"\n\nrule {name}\n{{\n    meta:\n        author = "SPECIMEN (auto)"\n'
                f'        sample_sha256 = "{sha256}"\n        confidence = "auto-generated; review before deploy"\n'
                f"    condition:\n        uint16(0) == 0x5A4D and (\n        "
                + "\n        or ".join(conds) + "\n        )\n}\n")


def synthesize_yara_pe(static_tokens: Sequence[str], negatives: Sequence[set[str]],
                       prevalence: dict[str, float] | None = None, k: int = 8,
                       frac: float = 0.75, with_imphash: bool = True) -> YaraPeRule | None:
    """imphash OR >= ``frac`` of the ``k`` rarest imports; dropped if it hits a negative."""
    toks = set(static_tokens)
    imph = next((t.split(":", 1)[1] for t in toks if t.startswith("imphash:")), "")
    imps = [t for t in toks if t.startswith("imp:")]
    prevalence = prevalence or {}
    imps.sort(key=lambda t: (prevalence.get(t, 0.0), t))
    chosen = [tuple(t.split(":", 2)[1:]) for t in imps[:k] if prevalence.get(t, 0.0) < 0.05]
    need = max(2, int(round(frac * len(chosen)))) if chosen else 0
    rule = YaraPeRule(imph if with_imphash else "", tuple(chosen) if len(chosen) >= 3 else (), need)  # type: ignore[arg-type]
    if not rule.imphash and not rule.imports:
        return None
    if rule.imports and any(YaraPeRule("", rule.imports, need).matches(n) for n in negatives):
        rule = YaraPeRule(rule.imphash, (), 0)
    if rule.imphash and any(f"imphash:{rule.imphash}" in n for n in negatives):
        rule = YaraPeRule("", rule.imports, rule.need)
    return rule if (rule.imphash or rule.imports) else None
