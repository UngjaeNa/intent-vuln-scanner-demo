"""모듈 5: Report Generator - 세 탐지기 결과를 하나의 리포트로 병합."""
import json
import dataclasses
from datetime import datetime, timezone

# CWE/MASVS 매핑 - 조사한 CVE 사례 기준
MAPPING = {
    "spoofing": {"cwe": "CWE-926 (Improper Export of Android Application Components)",
                 "masvs": "MASVS-PLATFORM-1"},
    "injection": {"cwe": "CWE-927 (Use of Implicit Intent for Sensitive Communication)",
                  "masvs": "MASVS-PLATFORM-2"},
    "redirection": {"cwe": "CWE-926 (Intent Redirection)",
                     "masvs": "MASVS-PLATFORM-1"},
}


def _to_dict(obj):
    return dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else obj


def generate_report(apk_path: str, package: str, results: dict[str, list], chains: list | None = None) -> dict:
    report = {
        "apk": apk_path,
        "package": package,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {k: len(v) for k, v in results.items()},
        "findings": {},
    }
    for vuln_type, findings in results.items():
        report["findings"][vuln_type] = {
            "cwe": MAPPING[vuln_type]["cwe"],
            "masvs": MAPPING[vuln_type]["masvs"],
            "items": [_to_dict(f) for f in findings],
        }

    if chains is not None:
        report["summary"]["chain (2-hop, 보강분석)"] = len(chains)
        report["chains"] = {
            "description": "Spoofing/Injection/Redirection과 별개 항목이 아니라, "
            "메소드 간(inter-procedural) 흐름까지 이어서 기존 취약점 판정을 보강하는 분석",
            "items": [_to_dict(c) for c in chains],
        }
    return report


def save_report(report: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
