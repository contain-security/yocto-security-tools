#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a patch differences report from integration test results.

Parses the results CSV, *_differences.txt, and *_differences_diff.patch files
to produce a comprehensive markdown report summarizing how generated patches
differ from the original reference patches.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


def parse_differences_txt(path: Path) -> dict[str, Any]:
    """Parse a CVE differences.txt file into structured data."""
    info: dict[str, Any] = {
        "original_patches": [],
        "generated_patches": [],
        "original_files": 0,
        "generated_files": 0,
        "missing_files": [],
        "extra_files": [],
        "diff_lines": 0,
        "is_equivalent": False,
        "only_original": [],
        "only_generated": [],
    }
    text = path.read_text(errors="replace")
    section = None

    for line in text.splitlines():
        if line.startswith("Original patches"):
            if ":" in line:
                patches_str = line.split(":", 1)[1].strip()
                info["original_patches"] = [p.strip() for p in patches_str.split(",") if p.strip()]
        elif line.startswith("Generated patches"):
            if ":" in line:
                patches_str = line.split(":", 1)[1].strip()
                info["generated_patches"] = [p.strip() for p in patches_str.split(",") if p.strip()]
        elif line.startswith("Files touched"):
            parts = line.split(",")
            for part in parts:
                if "original:" in part:
                    try:
                        info["original_files"] = int(part.split(":")[-1].strip())
                    except ValueError:
                        pass
                if "generated:" in part:
                    try:
                        info["generated_files"] = int(part.split(":")[-1].strip())
                    except ValueError:
                        pass
        elif line.startswith("  Missing in generated:"):
            info["missing_files"] = [f.strip() for f in line.split(":", 1)[1].split(",") if f.strip()]
        elif line.startswith("  Extra in generated:"):
            info["extra_files"] = [f.strip() for f in line.split(":", 1)[1].split(",") if f.strip()]
        elif line.startswith("Differences:"):
            try:
                info["diff_lines"] = int(line.split(":")[1].strip().split()[0])
            except (ValueError, IndexError):
                pass
        elif "Patches are equivalent" in line:
            info["is_equivalent"] = True
        elif line.startswith("--- Only in original ---"):
            section = "original"
        elif line.startswith("+++ Only in generated +++"):
            section = "generated"
        elif section == "original" and line.startswith(("+", "-")):
            info["only_original"].append(line)
        elif section == "generated" and line.startswith(("+", "-")):
            info["only_generated"].append(line)

    return info


def parse_results_csv(csv_path: Path) -> list[dict[str, str]]:
    """Parse the results CSV into a list of row dicts."""
    rows: list[dict[str, str]] = []
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def _get_info(d: dict[str, Any]) -> dict[str, Any]:
    """Extract the info dict from a diff entry, asserting non-None."""
    info = d["info"]
    assert info is not None  # noqa: S101
    return info


def generate_report(results_dir: Path) -> str:
    """Generate the full differences report as markdown text."""
    csv_path = results_dir / "results_full.csv"
    if not csv_path.exists():
        sys.exit(f"ERROR: {csv_path} not found")

    rows = parse_results_csv(csv_path)

    # Categorize results
    identical: list[dict[str, str]] = []
    with_changes: list[dict[str, str]] = []
    agent_resolved: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    for row in rows:
        status = row.get("status", "")
        if status in ("IDENTICAL", "ALREADY_APPLIED"):
            identical.append(row)
        elif status == "AGENT_RESOLVED":
            agent_resolved.append(row)
        elif status == "SUCCESS":
            with_changes.append(row)
        elif status.startswith("FAIL"):
            failed.append(row)
        elif status.startswith("SKIP"):
            skipped.append(row)

    # Collect difference details for CVEs with changes
    diff_details: list[dict[str, Any]] = []
    for row in with_changes + agent_resolved:
        cve_id = row["cve_id"]
        diff_txt = results_dir / f"{cve_id}_differences.txt"
        diff_patch = results_dir / f"{cve_id}_differences_diff.patch"
        info = parse_differences_txt(diff_txt) if diff_txt.exists() else None
        patch_size = diff_patch.stat().st_size if diff_patch.exists() else 0
        diff_details.append({
            "row": row,
            "info": info,
            "patch_size": patch_size,
            "has_diff_patch": diff_patch.exists(),
        })

    # Sort by diff size (largest differences first)
    diff_details.sort(key=lambda d: int(d["patch_size"]), reverse=True)

    # Group by recipe
    by_recipe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in diff_details:
        by_recipe[d["row"]["recipe"]].append(d)

    # Build report
    lines: list[str] = []
    lines.append("# Patch Differences Report")
    lines.append("")
    lines.append(f"**Results directory:** `{results_dir}`")
    lines.append("")

    # Summary table
    total = len(rows)
    testable = len(identical) + len(with_changes) + len(agent_resolved) + len(failed)
    success = len(identical) + len(with_changes) + len(agent_resolved)
    pct = (success * 100 // testable) if testable > 0 else 0

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total CVEs | {total} |")
    lines.append(f"| Identical (no diff) | {len(identical)} |")
    lines.append(f"| Success with changes | {len(with_changes)} |")
    lines.append(f"| Agent resolved | {len(agent_resolved)} |")
    lines.append(f"| Failed | {len(failed)} |")
    lines.append(f"| Skipped | {len(skipped)} |")
    lines.append(f"| Success rate | {pct}% ({success}/{testable}) |")
    lines.append("")

    # Difference severity distribution
    lines.append("## Difference Severity Distribution")
    lines.append("")
    whitespace_only: list[dict[str, Any]] = []
    minor_changes: list[dict[str, Any]] = []
    moderate_changes: list[dict[str, Any]] = []
    major_changes: list[dict[str, Any]] = []
    file_mismatch: list[dict[str, Any]] = []

    for d in diff_details:
        info = d["info"]
        if not info:
            continue
        if info["is_equivalent"]:
            whitespace_only.append(d)
        elif info["missing_files"] or info["extra_files"]:
            file_mismatch.append(d)
        elif info["diff_lines"] <= 10:
            minor_changes.append(d)
        elif info["diff_lines"] <= 50:
            moderate_changes.append(d)
        else:
            major_changes.append(d)

    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| Whitespace/formatting only | {len(whitespace_only)} |")
    lines.append(f"| Minor (1-10 lines) | {len(minor_changes)} |")
    lines.append(f"| Moderate (11-50 lines) | {len(moderate_changes)} |")
    lines.append(f"| Major (50+ lines) | {len(major_changes)} |")
    lines.append(f"| File mismatch (different files touched) | {len(file_mismatch)} |")
    lines.append("")

    # File mismatch details
    if file_mismatch:
        lines.append("## File Mismatches")
        lines.append("")
        lines.append("CVEs where the generated patch touches different files than the original:")
        lines.append("")
        lines.append("| CVE | Recipe | Missing Files | Extra Files |")
        lines.append("|-----|--------|---------------|-------------|")
        for d in file_mismatch:
            row = d["row"]
            info = _get_info(d)
            missing = ", ".join(info["missing_files"][:3])
            extra = ", ".join(info["extra_files"][:3])
            lines.append(f"| {row['cve_id']} | {row['recipe']} | {missing} | {extra} |")
        lines.append("")

    # Major changes details
    if major_changes:
        lines.append("## Major Differences (50+ lines)")
        lines.append("")
        lines.append("| CVE | Recipe | Diff Lines | Patch Size | Files (orig\u2192gen) |")
        lines.append("|-----|--------|-----------|------------|------------------|")
        for d in major_changes:
            row = d["row"]
            info = _get_info(d)
            lines.append(
                f"| {row['cve_id']} | {row['recipe']} "
                f"| {info['diff_lines']} | {d['patch_size']} B "
                f"| {info['original_files']}\u2192{info['generated_files']} |"
            )
        lines.append("")

    # Moderate changes
    if moderate_changes:
        lines.append("## Moderate Differences (11-50 lines)")
        lines.append("")
        lines.append("| CVE | Recipe | Diff Lines | Patch Size |")
        lines.append("|-----|--------|-----------|------------|")
        for d in moderate_changes:
            row = d["row"]
            info = _get_info(d)
            lines.append(
                f"| {row['cve_id']} | {row['recipe']} | {info['diff_lines']} | {d['patch_size']} B |"
            )
        lines.append("")

    # Minor changes
    if minor_changes:
        lines.append("## Minor Differences (1-10 lines)")
        lines.append("")
        lines.append("| CVE | Recipe | Diff Lines | Patch Size |")
        lines.append("|-----|--------|-----------|------------|")
        for d in minor_changes:
            row = d["row"]
            info = _get_info(d)
            lines.append(
                f"| {row['cve_id']} | {row['recipe']} | {info['diff_lines']} | {d['patch_size']} B |"
            )
        lines.append("")

    # Per-recipe summary
    lines.append("## Per-Recipe Summary")
    lines.append("")
    lines.append("| Recipe | CVEs with Diffs | Avg Diff Lines | Max Diff Lines |")
    lines.append("|--------|-----------------|----------------|----------------|")
    for recipe in sorted(by_recipe.keys()):
        entries = by_recipe[recipe]
        diff_lines_list = [
            e["info"]["diff_lines"]
            for e in entries
            if e["info"] and not e["info"]["is_equivalent"]
        ]
        if not diff_lines_list:
            continue
        avg_lines = sum(diff_lines_list) // len(diff_lines_list)
        max_lines = max(diff_lines_list)
        lines.append(f"| {recipe} | {len(diff_lines_list)} | {avg_lines} | {max_lines} |")
    lines.append("")

    # Recipe clustering by divergence type
    lines.append("## Recipe Clusters by Divergence Type")
    lines.append("")

    # Classify each recipe's dominant divergence pattern
    cluster_whitespace: list[str] = []  # only whitespace/formatting diffs
    cluster_context: list[str] = []  # minor context line shifts (1-10 lines, same files)
    cluster_logic: list[str] = []  # different code logic (>10 lines, same files)
    cluster_scope: list[str] = []  # touches different files
    cluster_mixed: list[str] = []  # multiple divergence types

    for recipe in sorted(by_recipe.keys()):
        entries = by_recipe[recipe]
        has_ws = False
        has_context = False
        has_logic = False
        has_scope = False
        for e in entries:
            info = e["info"]
            if not info:
                continue
            if info["is_equivalent"]:
                has_ws = True
            elif info["missing_files"] or info["extra_files"]:
                has_scope = True
            elif info["diff_lines"] <= 10:
                has_context = True
            else:
                has_logic = True

        types = sum([has_ws, has_context, has_logic, has_scope])
        if types == 0:
            continue
        elif types > 1:
            cluster_mixed.append(recipe)
        elif has_ws:
            cluster_whitespace.append(recipe)
        elif has_context:
            cluster_context.append(recipe)
        elif has_logic:
            cluster_logic.append(recipe)
        elif has_scope:
            cluster_scope.append(recipe)

    lines.append("### Cluster 1: Whitespace/Formatting Only")
    lines.append("")
    lines.append("Patches are semantically identical — differences are only in indentation or "
                 "formatting.")
    lines.append("")
    if cluster_whitespace:
        lines.append(f"**Recipes ({len(cluster_whitespace)}):** "
                     + ", ".join(f"`{r}`" for r in cluster_whitespace))
    else:
        lines.append("*(none)*")
    lines.append("")

    lines.append("### Cluster 2: Minor Context Shifts (≤10 lines)")
    lines.append("")
    lines.append("Small differences in surrounding context lines or trivial code variations "
                 "(version strings, comment tweaks). Same files touched.")
    lines.append("")
    if cluster_context:
        lines.append(f"**Recipes ({len(cluster_context)}):** "
                     + ", ".join(f"`{r}`" for r in cluster_context))
    else:
        lines.append("*(none)*")
    lines.append("")

    lines.append("### Cluster 3: Significant Logic Differences (>10 lines)")
    lines.append("")
    lines.append("Substantial code differences — the generated patch implements the fix "
                 "differently than the original. Same files touched.")
    lines.append("")
    if cluster_logic:
        lines.append(f"**Recipes ({len(cluster_logic)}):** "
                     + ", ".join(f"`{r}`" for r in cluster_logic))
    else:
        lines.append("*(none)*")
    lines.append("")

    lines.append("### Cluster 4: Different File Scope")
    lines.append("")
    lines.append("The generated patch touches different files than the original — "
                 "the fix was applied in a different location or includes extra/missing changes.")
    lines.append("")
    if cluster_scope:
        lines.append(f"**Recipes ({len(cluster_scope)}):** "
                     + ", ".join(f"`{r}`" for r in cluster_scope))
    else:
        lines.append("*(none)*")
    lines.append("")

    lines.append("### Cluster 5: Mixed Divergence")
    lines.append("")
    lines.append("Multiple CVEs for this recipe diverge in different ways "
                 "(combination of the above patterns).")
    lines.append("")
    if cluster_mixed:
        lines.append(f"**Recipes ({len(cluster_mixed)}):** "
                     + ", ".join(f"`{r}`" for r in cluster_mixed))
    else:
        lines.append("*(none)*")
    lines.append("")

    # Failed CVEs
    if failed:
        lines.append("## Failed CVEs")
        lines.append("")
        lines.append("| CVE | Recipe | Exit Code |")
        lines.append("|-----|--------|-----------|")
        for row in failed:
            lines.append(f"| {row['cve_id']} | {row['recipe']} | {row['exit_code']} |")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    """Entry point for the differences report generator."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results_dir",
        type=Path,
        help="Path to the test results directory (e.g., bulk_20260626_081658)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output file path (default: <results_dir>/differences_report.md)",
    )
    args = parser.parse_args()

    if not args.results_dir.is_dir():
        sys.exit(f"ERROR: {args.results_dir} is not a directory")

    report = generate_report(args.results_dir)

    output_path = args.output or (args.results_dir / "differences_report.md")
    output_path.write_text(report)
    print(f"Report written to: {output_path}")


if __name__ == "__main__":
    main()
