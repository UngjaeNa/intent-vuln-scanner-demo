"""
Intent Redirection Detector
판정 로직 (2단계):
  1차: 같은 메소드 안에서 getParcelableExtra(Intent 추출 후보)와
       startActivity류(재실행)가 함께 호출되고, resolveActivity 등 검증 호출이 없는 경우
  2차(타입 필터): core/type_resolver.py 로 getParcelableExtra의 반환값이
       실제로 Intent 타입(check-cast)으로 확인되는 경우만 최종 채택.
       -> 문자열/Bundle 등 다른 Parcelable을 꺼내는 케이스는 여기서 걸러짐 (오탐 감소)

3차(중요): Redirection의 위험은 "재전달(forward)하는 컴포넌트 자체가 외부에서
호출 가능한가"에 달려 있다 - 공격자가 애초에 이 컴포넌트에 도달할 수 없으면
악성 Intent를 실어 보낼 수 없다. 그래서 c.caller_class(재전달을 실행하는 클래스)의
도달가능성을 확인해 reachability 필드로 명시한다.
"""

from dataclasses import dataclass
from core.api_locator import ApiLocator
from core.rule_loader import load_rule
from core.type_resolver import find_parcelable_extra_casts
from core.reachability import ReachabilityIndex
from dataflow.heuristic import method_level_candidates
from dataflow.register_link import find_flow_evidence


@dataclass
class RedirectionFinding:
    location: str
    reason: str
    matched_sources: list[str]
    matched_sinks: list[str]
    type_confirmed: bool   # True면 check-cast로 Intent 타입까지 확인된 고신뢰 케이스
    reachability: str       # "direct" | "chain" | "unknown"
    reachability_note: str
    severity: str = "high"


class RedirectionDetector:
    def __init__(self, apk_path: str, chain_findings: list | None = None):
        self.apk_path = apk_path
        self.rule = load_rule("redirection")
        self.locator = ApiLocator(apk_path)
        injection_rule = load_rule("injection")
        if chain_findings is not None:
            self._chain_findings = chain_findings
        else:
            from detectors.chain import ChainDetector
            self._chain_findings = ChainDetector(apk_path).run()
        self.reach_index = ReachabilityIndex(apk_path, self.locator, self._chain_findings)

    def _get_method_instructions(self, caller_class: str, caller_method: str, caller_descriptor: str):
        return self.locator.get_method_instructions(caller_class, caller_method, caller_descriptor)

    def run(self) -> list[RedirectionFinding]:
        candidates = method_level_candidates(
            self.locator,
            sources=self.rule["sources"],
            sinks=self.rule["sinks"],
            validators=self.rule.get("validators", []),
        )
        findings = []
        for c in candidates:
            has_parcelable_source = any("getParcelableExtra" in s for s in c.matched_sources)

            instructions = self._get_method_instructions(
                c.caller_class, c.caller_method, c.caller_descriptor
            )

            type_confirmed = False
            if has_parcelable_source and instructions:
                casts = find_parcelable_extra_casts(instructions)
                type_confirmed = any(cast.is_intent_type for cast in casts)
                if casts and not type_confirmed and all(
                    cast.cast_type is not None for cast in casts
                ):
                    continue

            register_confirmed = False
            if instructions:
                evidence = find_flow_evidence(instructions, self.rule["sources"], self.rule["sinks"])
                register_confirmed = len(evidence) > 0

            if not has_parcelable_source and not register_confirmed:
                continue

            reach = self.reach_index.classify(c.caller_class)

            if reach.level == "unknown":
                severity = "low"  # 재전달 컴포넌트 자체에 도달 못하면 이 취약점은 발동 불가
            elif type_confirmed or register_confirmed:
                severity = "high"
            else:
                severity = "medium"

            findings.append(
                RedirectionFinding(
                    location=f"{c.caller_class}#{c.caller_method}{c.caller_descriptor}",
                    reason=(
                        "Intent 추출 API와 재실행(startActivity 등) API가 "
                        "같은 메소드 안에 존재하며, resolveActivity 등 목적지 검증 호출이 없음"
                        + (" (check-cast로 Intent 타입까지 확인됨)" if type_confirmed else "")
                        + (" (레지스터 단위로 연결까지 확인됨)" if register_confirmed else "")
                    ),
                    matched_sources=c.matched_sources,
                    matched_sinks=c.matched_sinks,
                    type_confirmed=type_confirmed,
                    reachability=reach.level,
                    reachability_note=reach.note,
                    severity=severity,
                )
            )
        return findings


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("사용법: python -m detectors.redirection <apk_path>")
        sys.exit(1)

    detector = RedirectionDetector(sys.argv[1])
    results = detector.run()
    print(f"Intent Redirection 취약 후보: {len(results)}건\n")
    for r in results:
        print(json.dumps(r.__dict__, indent=2, ensure_ascii=False))
