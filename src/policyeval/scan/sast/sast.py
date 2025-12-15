from collections import Counter
from typing import List
import json

from policyeval.policy import load_policy
from collections import defaultdict



# Internal severity ordering
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

#  Opengrep : Internal severity
SEMGREP_SEVERITY_MAP = {
    "INFO": "LOW",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
}


def _evaluate_operator(count: int, operator: str, threshold: int) -> bool:
    """
    Returns True ONLY when the policy is violated.
    Policy semantics = MAX allowed findings
    """
    if operator == ">=":
        return count >= threshold      
    if operator == ">":
        return count > threshold
    if operator == "<=":
        return count > threshold
    if operator == "<":
        return count >= threshold
    return False


def evaluate(scan_results: dict, policies: list[dict]) -> dict:
    summary_counts = defaultdict(int)
    failures = []

    # Count severity in scan results (normalized)
    for item in scan_results.get("results", []):
        raw_sev = item.get("extra", {}).get("severity", "INFO").upper()
        sev = SEMGREP_SEVERITY_MAP.get(raw_sev, "LOW")
        summary_counts[sev] += 1

    for policy in policies:
        rules = policy.get("rules", {})

        # Evaluate severity rules (if any)
        severity_rules = rules.get("severity", {})
        for sev, op_str in severity_rules.items():
            if not op_str:
                continue
            try:
                operator, threshold = op_str.strip().split()
                threshold = int(threshold)
            except Exception:
                continue
            count = summary_counts.get(sev, 0)
            if _evaluate_operator(count, operator, threshold):
                failures.append({
                    "policy": policy["policy_name"],
                    "type": "severity",
                    "severity": sev,
                    "count": count,
                    "rule": op_str,
                    "message": f"{sev} findings count {count} violates rule {op_str}"
                })

        # Evaluate block_if_cwe rules (if any)
        cwe_rules = set(rules.get("block_if_cwe", []))

        if cwe_rules:
            found_cwes = set()

            for item in scan_results.get("results", []):
                metadata = item.get("extra", {}).get("metadata", {})
                cwes = metadata.get("cwe", [])

                if isinstance(cwes, str):
                    cwes = [cwes]

                for raw_cwe in cwes:
                    cwe_id = raw_cwe.split(":")[0].strip()

                    if cwe_id in cwe_rules:
                        found_cwes.add(cwe_id)

            # Emit ONE failure per CWE per policy
            for cwe_id in sorted(found_cwes):
                failures.append({
                    "policy": policy["policy_name"],
                    "type": "cwe",
                    "cwe": cwe_id,
                    "message": f"{cwe_id} found in scan results, blocked by policy"
                })

    passed = len(failures) == 0
    return {"passed": passed, "summary": dict(summary_counts), "failures": failures}
