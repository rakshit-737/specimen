# How it works

This page follows one bundled input, `tests/fixtures/cape/avast_njrat_1.json` (a trimmed public Avast-CTU CAPEv2 report of an njRAT sample), through every stage. The full output is the [njRAT demo report](demo/avast_njrat_1.md); run it yourself with `python -m specimen report tests/fixtures/cape/avast_njrat_1.json` after `python scripts/fetch_models.py --only family_`. The numbers on this page are generated from `docs/demo/summary.json`, which `scripts/build_demo.py` writes with the pinned family model.

```mermaid
flowchart TB
  R["CAPE report"] --> A["Adapter"]
  A --> T["Trace (typed events)"]
  T --> P["Provenance graph + ATT&CK timeline"]
  T --> B["Behaviour scorer"]
  T --> F["Family model"]
  T --> S["Sigma / YARA synthesis"]
  F -.->|"predicted family left out of the negatives"| S
  P --> REP["Report + manifest"]
  B --> REP
  F --> REP
  S --> REP
```

## 1. Static gate

A reduced report carries `static.pe` (imports, sections, imphash), not the sample bytes. <!-- gen:walk-static -->
The PE-metadata heuristic scores it 0.2315 (top reason `pe_executable` +0.80).
<!-- /gen:walk-static -->
For a real PE, `analyze` still replays every PE; the trained EMBER LightGBM gate is a separate `triage-ember` command because SPECIMEN has no PE-to-EMBER feature extractor ([Evaluation](benchmarks.md#1-static-gate-on-ember)).

## 2. Adapter to trace

`specimen/adapters/cape.py` maps `behavior.summary` (files, keys, mutexes, executed commands, resolved APIs) and full call logs onto one `Trace` of typed events: `process_create`, `file_write`, `registry_set`, `dns_query`, `net_connect`, `mutex_create` and more. Unknown shapes are ignored; values are coerced to strings and capped; non-finite numbers are refused. Reduced reports have no timing, so events are ordered deterministically and flagged `synthetic_ts`. Sysmon exports and Speakeasy emulation reports go through their own adapters into the same event model.

## 3. Provenance graph and timeline

`specimen/provenance.py` builds the process tree plus file, registry, network, mutex and service edges, and tags events with about 50 ATT&CK rules. The graph of this run, as the report renders it:

<!-- gen:walk-graph -->
```mermaid
flowchart LR
  n0["process: sample.exe (1000)"]
  n1["mutex: bitsperf"]
  n2["mutex: Global\CLR_CASOFF_MUTEX"]
  n3["mutex: 10e93180d6481ad63a77c2b255d40864"]
  n4["mutex: Global\.net clr networking"]
  n5["process: RegAsm.exe (1001)"]
  n6["process: netsh (1002)"]
  n7["file: C:\Windows\WindowsShell.Manifest"]
  n8["file: \Device\KsecDD"]
  n9["file: C:\Users\comp\AppData\Local\Temp\83DFFD621EFA44CF1A60.exe"]
  n10["file: C:\Windows\Globalization\Sorting\sortdefault.nls"]
  n11["file: C:\Windows\System32\UxTheme.dll[.]Config"]
  n12["file: C:\Windows\System32\uxtheme.dll"]
  n13["file: C:\Users\comp\service\svchost.exe"]
  n14["file: C:\Users\comp\AppData\Roaming~ocess for Windows Services.url"]
  n15["file: C:\Users\comp\service\Host Process for Windows Services.vbs"]
  n16["file: C:\Windows\Microsoft.NET\Fram~k\v2.0.50727\RegAsm.exe[.]config"]
  n17["file: C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorwks.dll"]
  n18["file: C:\Windows\winsxs\x86_microso~e_d08cc06a442b34fc\msvcr80.dll"]
  n19["file: C:\Users"]
  n20["file: C:\Users\comp"]
  n21["file: C:\Users\comp\AppData"]
  n22["file: C:\Users\comp\AppData\Local"]
  n23["file: C:\Users\comp\AppData\Local\Temp"]
  n24["file: C:\Users\comp\AppData\Local\T~3DFFD621EFA44CF1A60.exe.Local\"]
  n25["file: \Device\Http\Communication"]
  n26["registry: HKEY_CURRENT_USER\di"]
  n27["registry: HKEY_CURRENT_USER\Environment\SEE_MASK_NOZONECHECKS"]
  n28["registry: HKEY_CURRENT_USER\Software\10e93180d6481ad63a77c2b255d40864"]
  n29["registry: HKEY_CURRENT_USER\Software\10~0d6481ad63a77c2b255d40864\(kl)"]
  n30["registry: HKEY_CURRENT_USER\Software\Cl~iCache\6\52C64B7E\LanguageList"]
  n31["registry: HKEY_CURRENT_USER\Software\Cl~oot%\system32\dhcpqec.dll,-100"]
  n32["registry: HKEY_CURRENT_USER\Software\Cl~oot%\system32\dhcpqec.dll,-101"]
  n33["registry: HKEY_CURRENT_USER\Software\Cl~oot%\system32\dhcpqec.dll,-103"]
  n34["registry: HKEY_CURRENT_USER\Software\Cl~oot%\system32\dhcpqec.dll,-102"]
  n35["registry: HKEY_CURRENT_USER\Software\Cl~Root%\system32\napipsec.dll,-1"]
  n36["registry: HKEY_CURRENT_USER\Software\Cl~Root%\system32\napipsec.dll,-2"]
  n37["registry: HKEY_CURRENT_USER\Software\Cl~Root%\system32\napipsec.dll,-4"]
  n38["registry: HKEY_LOCAL_MACHINE\SOFTWARE\W~tings\DisableImprovedZoneCheck"]
  n39["registry: HKEY_LOCAL_MACHINE\SOFTWARE\P~et Settings\Security_HKLM_only"]
  n40["registry: DisableUserModeCallbackFilter"]
  n41["registry: HKEY_CURRENT_USER\Control Panel\Mouse\SwapMouseButtons"]
  n42["registry: HKEY_LOCAL_MACHINE\SYSTEM\Con~Control\Nls\CustomLocale\en-US"]
  n43["registry: HKEY_LOCAL_MACHINE\SYSTEM\Con~ntrol\Nls\ExtendedLocale\en-US"]
  n44["registry: HKEY_LOCAL_MACHINE\SYSTEM\Con~ing\Versions\00060101[.]00060101"]
  n45["registry: HKEY_LOCAL_MACHINE\SYSTEM\Con~01\Control\Nls\Locale\00000409"]
  n46["registry: HKEY_LOCAL_MACHINE\SYSTEM\Con~\Control\Nls\Language Groups\1"]
  n47["registry: HKEY_LOCAL_MACHINE\SYSTEM\Con~AccessProviders\MartaExtension"]
  n48["registry: HKEY_LOCAL_MACHINE\SOFTWARE\M~RE_Initialize\DisableMetaFiles"]
  n49["registry: HKEY_LOCAL_MACHINE\SOFTWARE\W~soft\.NETFramework\InstallRoot"]
  n50["registry: HKEY_LOCAL_MACHINE\Software\M~dows\CurrentVersion\SideBySide"]
  n51["registry: HKEY_LOCAL_MACHINE\system\Cur~ontrol\NetworkProvider\HwOrder"]
  n52["registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OLEAUT"]
  n53["registry: HKEY_LOCAL_MACHINE\Software\M~rrentVersion\Internet Settings"]
  n54["registry: HKEY_LOCAL_MACHINE\Software\P~rrentVersion\Internet Settings"]
  n55["registry: HKEY_CURRENT_USER\Control Panel\Mouse"]
  n56["registry: HKEY_CURRENT_USER\Software\AutoIt v3\AutoIt"]
  n57["registry: HKEY_LOCAL_MACHINE\System\Cur~olSet\Control\Nls\CustomLocale"]
  n0 -->|"created"| n1
  n0 -->|"created"| n2
  n0 -->|"created"| n3
  n0 -->|"created"| n4
  n0 -->|"spawned"| n5
  n0 -->|"spawned"| n6
  n0 -->|"read"| n7
  n0 -->|"read"| n8
  n0 -->|"read"| n9
  n0 -->|"read"| n10
  n0 -->|"read"| n11
  n0 -->|"read"| n12
  n0 -->|"read"| n13
  n0 -->|"read"| n14
  n0 -->|"read"| n15
  n0 -->|"read"| n16
  n0 -->|"read"| n17
  n0 -->|"read"| n18
  n0 -->|"read"| n19
  n0 -->|"read"| n20
  n0 -->|"read"| n21
  n0 -->|"read"| n22
  n0 -->|"read"| n23
  n0 -->|"read"| n24
  n0 -->|"wrote"| n13
  n0 -->|"wrote"| n14
  n0 -->|"wrote"| n15
  n0 -->|"wrote"| n25
  n0 -->|"set"| n26
  n0 -->|"set"| n27
  n0 -->|"set"| n28
  n0 -->|"set"| n29
  n0 -->|"set"| n30
  n0 -->|"set"| n31
  n0 -->|"set"| n32
  n0 -->|"set"| n33
  n0 -->|"set"| n34
  n0 -->|"set"| n35
  n0 -->|"set"| n36
  n0 -->|"set"| n37
  n0 -->|"read"| n38
  n0 -->|"read"| n39
  n0 -->|"read"| n40
  n0 -->|"read"| n41
  n0 -->|"read"| n42
  n0 -->|"read"| n43
  n0 -->|"read"| n44
  n0 -->|"read"| n45
  n0 -->|"read"| n46
  n0 -->|"read"| n47
  n0 -->|"read"| n48
  n0 -->|"read"| n49
  n0 -->|"read"| n50
  n0 -->|"read"| n51
  n0 -->|"read"| n52
  n0 -->|"read"| n53
  n0 -->|"read"| n54
  n0 -->|"read"| n55
  n0 -->|"read"| n56
  n0 -->|"read"| n57
```
<!-- /gen:walk-graph -->

The timeline rows that carry an ATT&CK technique (every report string is entity-encoded and IOCs are defanged in the Markdown report):

<!-- gen:walk-timeline -->
| t | event | ATT&CK |
|---|---|---|
| 0.03 | sample.exe wrote C:\Users\comp\service\svchost.exe | T1105 command-and-control |
| 0.03 | sample.exe wrote C:\Users\comp\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Host Process for Windows Services.url | T1547.001 persistence |
| 0.03 | sample.exe wrote C:\Users\comp\service\Host Process for Windows Services.vbs | T1105 command-and-control |
<!-- /gen:walk-timeline -->

## 4. Behaviour score

Traces with at least 5 real API calls are scored by the packaged MalbehavD-V1 n-gram LR; reduced reports have no call log, so they get the MVP ATT&CK-feature scorer. <!-- gen:walk-behaviour -->
Here the scorer is `mvp-synthetic-logreg (ATT&CK features)`, P(malicious) = 0.9133, driven by `n_drop` (+2.76), `n_persist` (+1.18), `n_file_write` (-0.04). Fused with the static score the verdict is **malicious** (0.9133, confidence medium (behavior-driven)).
<!-- /gen:walk-behaviour -->
The report always names the scorer used.

## 5. Family attribution

Events become normalised tokens (user names, GUIDs, SIDs, hex blobs and numbers removed) and a hashed-token LR trained on the Avast-CTU temporal training split predicts the family. <!-- gen:walk-family -->
Result for this run: **unknown (closest: njRAT), p = 0.821** (avast-ctu-logreg (behaviour+static)). The tokens that drove it: `tech:T1105 (+0.230)`, `tactic:command-and-control (+0.225)`, `tech:T1547.001 (+0.214)`, `tactic:persistence (+0.200)`.
<!-- /gen:walk-family -->
Below the abstain threshold (chosen on a validation slice) the report says `unknown (closest: X)` instead.

## 6. Sigma and YARA synthesis

For each host action of the run the synthesiser climbs a generalisation ladder ([ADR 0002](adr/0002-specificity-constrained-rule-generalisation.md)): rung 0 is the exact value, higher rungs replace user names, numbers, file stems and parent directories with wildcards. A rung is kept only if it still has at least 10 literal characters beyond generic prefixes (hive roots, `\Environment`, user profile folders) and hits nothing in the negative corpus: the synthetic benign traces plus the packaged Avast-CTU corpus *minus the family the model predicted* (without a family model nothing is left out). `analyze` and `report` use the same synthesizer.

<!-- gen:walk-sigma -->
This run yields 10 Sigma rules; the first (generalisation rung 2):

```yaml
detection:
    selection:
        TargetFilename: 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\*\\Host Process for Windows Services.url'
    condition: selection
```
<!-- /gen:walk-sigma -->

Literal segments are escaped for Sigma (`\`), wildcards are left unescaped, and every value is emitted through a YAML-safe quoter; CI compiles every emitted rule with pySigma and runs it in SQLite on its own run. YARA rules use `pe.imphash()` or the rarest imports by family prevalence. How far such rules generalise, and what they cost in false positives:

<img src="../figures/rule_generalisation.png" width="640" alt="Sibling recall against cross-family FPR per synthesizer">

## 7. Report and evidence manifest

The JSON and Markdown reports carry the verdict with a confidence grade, the static reasons, the timeline, the Mermaid graph, IOCs, rules and a manifest of SHA-256s (sample, trace, report and report content), the negative corpus used (and the family left out) and, for `analyze`, whether the trace is bound to the sample's hash. In report-only mode no sample bytes are handled: `sample_sha256` is taken from the report when present and is otherwise `null` with a note, and the report file's hash is recorded as `report_sha256` / `trace_sha256`.
