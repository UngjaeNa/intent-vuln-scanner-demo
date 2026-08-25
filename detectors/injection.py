"""
Intent Injection Detector
1차 판정: 같은 메소드 안에서 외부 입력 source(getStringExtra, getData 등)와
위험 sink(WebView.loadUrl, Runtime.exec 등)가 함께 호출되는 경우.

2차 보강: dataflow/register_link.py 로 source 결과 레지스터가 실제로 sink
인자로 이어지는지 확인. 이어지면 confidence를 high로 격상.

3차 보강(중요): 이 코드 패턴이 있다는 것만으로는 "Intent Injection"이라고
부를 수 없다 - 그 클래스가 실제로 외부에서 도달 가능해야(exported, 또는
체인으로 도달 확인) 비로소 Intent 기반 공격 표면이 된다. non-exported
클래스에 같은 패턴이 있어도 도달 경로가 증명되지 않으면 reachability를
"unknown"으로 명시하고, 이를 근거로 confidence를 강등한다 (실제
InsecureShop의 PrivateActivity 사례 - exported는 아니지만 WebView2Activity의
Redirection 취약점을 통해서만 간접 도달 가능했던 것을 계기로 추가됨).

주의: register_link는 필드 저장(iput/iget)이나 StringBuilder 조합을 거치는
흐름은 추적하지 못하는 알려진 한계가 있다 (실제 ViewStatement 사례로 확인됨).
그래서 "연결이 안 보인다"는 이유로 후보를 걸러내지 않는다 - 증거를 못 찾아도
1차 판정(co-occurrence)은 그대로 유지하고, 증거를 찾았을 때만 신뢰도를 올리는
방향으로만 쓴다 (미탐 방지 우선).
"""

from dataclasses import dataclass
from core.api_locator import ApiLocator
from core.rule_loader import load_rule
from core.reachability import ReachabilityIndex
from dataflow.heuristic import method_level_candidates
from dataflow.register_link import find_flow_evidence


@dataclass
class InjectionFinding:
    location: str
    reason: str
    matched_sources: list[str]
    matched_sinks: list[str]
    register_confirmed: bool  # True면 레지스터 단위로 source->sink 연결까지 확인된 고신뢰 케이스
    reachability: str          # "direct" | "chain" | "unknown"
    reachability_note: str
    confidence: str = "medium"


class InjectionDetector:
    def __init__(self, apk_path: str, chain_findings: list | None = None):
        self.apk_path = apk_path
        self.rule = load_rule("injection")
        self.locator = ApiLocator(apk_path)
        # 재사용 가능하면 외부(main.py)에서 이미 계산한 체인 결과를 받고,
        # 없으면 이 안에서 직접 계산 (단독 실행 시에도 동작하게)
        if chain_findings is not None:
            self._chain_findings = chain_findings
        else:
            from detectors.chain import ChainDetector
            self._chain_findings = ChainDetector(apk_path).run()
        self.reach_index = ReachabilityIndex(apk_path, self.locator, self._chain_findings)

    def run(self) -> list[InjectionFinding]:
        candidates = method_level_candidates(
            self.locator,
            sources=self.rule["sources"],
            sinks=self.rule["sinks"],
        )
        findings = []
        for c in candidates:
            is_webview = any("WebView" in s for s in c.matched_sinks)

            register_confirmed = False
            instructions = self.locator.get_method_instructions(
                c.caller_class, c.caller_method, c.caller_descriptor
            )
            if instructions:
                evidence = find_flow_evidence(instructions, self.rule["sources"], self.rule["sinks"])
                register_confirmed = len(evidence) > 0

            reach = self.reach_index.classify(c.caller_class)

            if reach.level == "unknown":
                # 도달 경로가 증명되지 않으면 아무리 코드 패턴이 확실해도 confidence를 낮춘다
                confidence = "low"
            elif register_confirmed:
                confidence = "high"
            elif is_webview:
                confidence = "high"
            else:
                confidence = "medium"

            findings.append(
                InjectionFinding(
                    location=f"{c.caller_class}#{c.caller_method}{c.caller_descriptor}",
                    reason=(
                        "외부 입력 source와 위험 sink가 같은 메소드 안에 함께 존재"
                        + (" (레지스터 단위로 연결까지 확인됨)" if register_confirmed else "")
                    ),
                    matched_sources=c.matched_sources,
                    matched_sinks=c.matched_sinks,
                    register_confirmed=register_confirmed,
                    reachability=reach.level,
                    reachability_note=reach.note,
                    confidence=confidence,
                )
            )
        return findings


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("사용법: python -m detectors.injection <apk_path>")
        sys.exit(1)

    detector = InjectionDetector(sys.argv[1])
    results = detector.run()
    print(f"Intent Injection 취약 후보: {len(results)}건\n")
    for r in results:
        print(json.dumps(r.__dict__, indent=2, ensure_ascii=False))
