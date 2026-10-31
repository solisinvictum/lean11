#!/usr/bin/env python3
"""Developer tool: curation sheet for one or more draft categories: each draft setting with its ops,
the verify status per op and the first lines of the source documentation.

usage: sheet.py draft.toml verify.json ops.json <category-substring>...
"""
import json
import sys
import tomllib

draft = tomllib.load(open(sys.argv[1], "rb"))
found = json.load(open(sys.argv[2]))
docs = {s["name"]: (" ".join(s["docs"]) if isinstance(s.get("docs"), list) else (s.get("docs") or "")) for s in json.load(open(sys.argv[3]))}
pats = sys.argv[4:]
by = {}
for f in found:
    by.setdefault(f["setting"], []).append(f)
for s in draft["setting"]:
    if not any(p in s["category"] for p in pats):
        continue
    name = s["sources"][0].split(": ", 1)[1]
    print(f"\n## {s['id']}  [{s['level']}]  cat={s['category']}\n   {name}")
    d = " ".join(docs.get(name, "").split())[:int(__import__("os").environ.get("DOCS","420"))]
    print(f"   docs: {d}")
    for f in by.get(s["id"], []):
        print(f"   {f['status']:<12} {f['op'][:120]}")
        if f["status"] not in ("ok",):
            print(f"                {f['detail'][:160]}")
