"""
Intent 2-hop 체인 탐지기
Spoofing/Injection/Redirection과 별개의 "4번째 취약점"이 아니라, 그 셋을
메소드 간(inter-procedural) 흐름까지 이어서 보강하는 분석이다.

한 메소드가 새 Intent를 만들어 다른 컴포넌트로 데이터를 전달하고, 그 컴포넌트가
같은 key로 값을 꺼내 위험한 sink로 쓰는 2단계 패턴을 찾는다. FlowDroid 같은
정밀 taint 분석 없이, register_link.py 방식을 메소드 간으로 확장한 것.
"""

from dataclasses import dataclass
from core.api_locator import ApiLocator
from core.rule_loader import load_rule
from dataflow.chain_link import find_chains


@dataclass
class ChainVulnFinding:
    hop1_location: str
    hop2_location: str
    key: str
    sink_call: str
    matched_sinks: list[str]
    reason: str


class ChainDetector:
    def __init__(self, apk_path: str):
        self.rule = load_rule("injection")
        self.locator = ApiLocator(apk_path)

    def run(self) -> list[ChainVulnFinding]:
        chains = find_chains(self.locator, self.rule["sinks"])
        findings = []
        for c in chains:
            findings.append(
                ChainVulnFinding(
                    hop1_location=f"{c.hop1.caller_class}#{c.hop1.caller_method}{c.hop1.caller_descriptor}",
                    hop2_location=f"{c.hop2_class}#{c.hop2_method}{c.hop2_descriptor}",
                    key=c.hop1.key,
                    sink_call=c.hop1.sink_call,
                    matched_sinks=c.matched_sinks,
                    reason=(
                        f"'{c.hop1.key}' 키로 값을 전달({c.hop1.sink_call})하고, "
                        f"대상 컴포넌트가 같은 키로 값을 꺼내 위험한 sink로 사용"
                    ),
                )
            )
        return findings


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("사용법: python -m detectors.chain <apk_path>")
        sys.exit(1)

    detector = ChainDetector(sys.argv[1])
    results = detector.run()
    print(f"2-hop 체인 발견: {len(results)}건\n")
    for r in results:
        print(json.dumps(r.__dict__, indent=2, ensure_ascii=False))
