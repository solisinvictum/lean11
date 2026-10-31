#!/usr/bin/env python3
"""Developer tool: expands a YAML script collection (windows.yaml) into leaf operations per script.

The result (JSON) is the worksheet for curating lean11's own privacy catalog
(crates/lean11-core/data/privacy.toml); it is not used at runtime.

usage: expand.py <collection checkout> > ops.json
"""
import json
import re
import sys

import yaml

# Functions kept as leaves (their parameters are the operation); everything else is expanded.
LEAVES = {
    "SetRegistryValue", "DeleteRegistryValue", "DeleteRegistryKey", "SoftDeleteRegistryKey", "CreateRegistryKey",
    "ClearRegistryValues", "DisableService", "DisableServiceInRegistry", "StopService", "StartService",
    "DisableScheduledTask", "BlockViaHostsFile", "UninstallStoreApp", "UninstallCapability", "DisableWindowsFeature",
    "SetMpPreference", "SoftDeleteFiles", "DeleteFiles", "ClearDirectoryContents", "DeleteDirectory", "DeleteGlob",
    "TerminateRunningProcess", "BlockExecutablesFromRunningViaShell", "SetJsonPropertyValue", "RemoveShortcutFiles",
    "CreatePlaceholderFile", "RunPowerShell", "RunPowerShellWithSetup", "RunPowerShellWithWindowsVersionConstraints",
    "RunPowerShellWithSameCodeAndRevertCode", "RunInlineCode", "DeleteFilesFromFirefoxProfiles",
}
IGNORED = {"Comment", "ShowMessage", "ShowExplorerRestartSuggestion", "ShowComputerRestartSuggestion",
           "ShowEdgeRestartSuggestion", "ShowChromeRestartSuggestion"}

TOKEN = re.compile(r"{{\s*(.*?)\s*}}", re.S)


def render(text, params):
    """Minimal template evaluation: $var, pipes (ignored), with/end blocks."""
    if not isinstance(text, str):
        return text
    out, pos, stack = [], 0, []  # stack: (emit_before, value)
    emit = True
    for m in TOKEN.finditer(text):
        if emit:
            out.append(text[pos:m.start()])
        pos = m.end()
        expr = m.group(1)
        if expr.startswith("with "):
            var = expr[5:].strip().split("|")[0].strip().lstrip("$")
            val = params.get(var)
            stack.append((emit, val))
            emit = emit and val not in (None, "", False)
        elif expr == "end":
            emit = stack.pop()[0] if stack else True
        elif emit:
            name = expr.split("|")[0].strip()
            if name == ".":
                val = stack[-1][1] if stack else ""
            else:
                val = params.get(name.lstrip("$"), "")
            out.append("" if val is None else str(val))
    if emit:
        out.append(text[pos:])
    return "".join(out)


def main():
    root = sys.argv[1]
    d = yaml.safe_load(open(f"{root}/src/application/collections/windows.yaml"))
    funcs = {f["name"]: f for f in d["functions"]}

    def expand(call, params, depth=0):
        name = call["function"]
        args = {k: render(v, params) for k, v in (call.get("parameters") or {}).items()}
        if name in IGNORED:
            return []
        if name in LEAVES or depth > 20:
            return [{"op": name, **{k: v for k, v in args.items() if v not in (None, "")}}]
        f = funcs[name]
        sub = f["call"] if isinstance(f["call"], list) else [f["call"]]
        res = []
        for c in sub:
            res.extend(expand(c, args, depth + 1))
        return res

    out = []

    def walk(node, path):
        for ch in node.get("children", []):
            if "children" in ch:
                walk(ch, path + [ch["category"]])
                continue
            ops = []
            if "call" in ch:
                calls = ch["call"] if isinstance(ch["call"], list) else [ch["call"]]
                for c in calls:
                    ops.extend(expand(c, {}))
            if "code" in ch:
                ops.append({"op": "RawCode", "code": ch["code"], "revertCode": ch.get("revertCode")})
            out.append({"path": path, "name": ch["name"], "recommend": ch.get("recommend"),
                        "docs": ch.get("docs"), "ops": ops})

    for cat in d["actions"]:
        walk(cat, [cat["category"]])
    json.dump(out, sys.stdout, indent=1, ensure_ascii=False)


if __name__ == "__main__":
    main()
