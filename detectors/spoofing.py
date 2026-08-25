"""
Intent Spoofing Detector
판정 로직: 공개(exported/암묵적 노출) 컴포넌트의 클래스 안에서
rules/spoofing.yaml 의 validators 목록에 있는 API가 단 한 번도 호출되지 않으면 취약 후보로 표시.

taint 분석이 필요 없는 "구조적 부재" 탐지이므로 Androguard(XREF)만으로 처리 가능.
"""

from dataclasses import dataclass, field
from core.manifest_parser import ManifestParser, ComponentInfo
from core.api_locator import ApiLocator
from core.rule_loader import load_rule, to_smali_class
from core.scope_filter import is_self_invocable, is_third_party
from core.dynamic_receiver import find_dynamic_receivers


@dataclass
class SpoofingFinding:
    component: str
    comp_type: str
    reason: str
    evidence: dict = field(default_factory=dict)
    severity: str = "medium"
    is_intent_based: bool = True  # False면 Intent 메커니즘과 무관 (예: ContentProvider)


class SpoofingDetector:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.rule = load_rule("spoofing")
        self.manifest = ManifestParser(apk_path)
        self.locator = ApiLocator(apk_path)

    def _validator_callers(self) -> set[str]:
        """validators 목록의 API를 실제로 호출하는 클래스 집합을 미리 전부 구해둔다.
        클래스 기반 검색이 기본. this.getCallingPackage() 처럼 자기자신 호출이
        실제로 발생하는 Activity/Context 계열 API만 이름 기반 검색도 병행한다
        (PackageManager.checkSignatures 같은 건 앱이 상속할 일이 없으므로 제외 -
        무관한 동명 메소드와 충돌 위험만 커짐)."""
        callers = set()
        for v in self.rule["validators"]:
            for call in self.locator.find_calls(v["class"], v["method"]):
                callers.add(call.caller_class)
            if is_self_invocable(v["class"]):
                for call in self.locator.find_calls_by_name(v["method"]):
                    callers.add(call.caller_class)
        return callers

    def run(self) -> list[SpoofingFinding]:
        findings: list[SpoofingFinding] = []
        components = self.manifest.get_public_components()
        validator_callers = self._validator_callers()

        for comp_type, comp_list in components.items():
            for comp in comp_list:
                if not comp.is_publicly_reachable:
                    continue

                smali_class = to_smali_class(comp.name)
                has_validation = smali_class in validator_callers

                if has_validation:
                    continue  # 검증 API 호출이 존재 -> 취약 후보에서 제외

                # ContentProvider는 Intent가 아니라 Uri 기반(ContentResolver)으로 접근한다.
                # "노출된 컴포넌트"라는 문제 자체는 같은 성격이지만, Intent 메커니즘과는
                # 무관하므로 "Intent Spoofing"이라는 이름을 붙이지 않는다.
                is_intent_based = comp_type != "provider"
                reason = (
                    "exported 컴포넌트이지만 발신자 검증 API "
                    "(getCallingPackage/checkSignatures 등) 호출이 발견되지 않음"
                    if is_intent_based else
                    "exported ContentProvider이며 발신자 검증 API 호출이 발견되지 않음 "
                    "(주의: ContentProvider는 Intent가 아니라 Uri 기반으로 접근되므로 "
                    "엄밀히는 'Intent Spoofing'이 아니라 별도의 컴포넌트 노출 문제임)"
                )

                findings.append(
                    SpoofingFinding(
                        component=comp.name,
                        comp_type=comp_type,
                        reason=reason,
                        evidence={
                            "exported": comp.exported,
                            "has_intent_filter": comp.has_intent_filter,
                            "permission": comp.permission,
                            "intent_actions": comp.intent_actions,
                        },
                        severity="high" if comp.permission is None else "medium",
                        is_intent_based=is_intent_based,
                    )
                )

        # 동적으로 registerReceiver() 등록되는 리시버 - 매니페스트엔 안 보이는 사각지대.
        # manifest_parser 가 못 보는 노출면을 여기서 보강한다.
        for dyn in find_dynamic_receivers(self.locator):
            if dyn.exposure not in ("exported", "unknown"):
                continue  # protected(permission 있음)는 스킵
            if is_third_party(dyn.name):
                continue  # 서드파티 SDK 내부 리시버 - injection/redirection과 동일한 이유로 제외

            has_validation = dyn.name in validator_callers
            if has_validation:
                continue

            findings.append(
                SpoofingFinding(
                    component=dyn.name.strip("L;").replace("/", "."),
                    comp_type="dynamic_receiver",
                    reason=(
                        f"코드에서 동적으로 등록된(registerReceiver, {dyn.arg_count}-인자) "
                        f"BroadcastReceiver이며 발신자 검증 API 호출이 발견되지 않음 "
                        f"(등록 위치: {dyn.registered_in})"
                        + (" - flags 오버로드라 노출 여부 수동 확인 필요" if dyn.exposure == "unknown" else "")
                    ),
                    evidence={
                        "exported": dyn.exposure == "exported",
                        "has_intent_filter": None,  # 매니페스트 기반 정보 없음 - 동적 등록이라 N/A
                        "permission": "있음" if dyn.has_permission_arg else None,
                        "intent_actions": [],
                        "registered_in": dyn.registered_in,
                    },
                    severity="high" if dyn.exposure == "exported" else "medium",
                )
            )
        return findings


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("사용법: python -m detectors.spoofing <apk_path>")
        sys.exit(1)

    detector = SpoofingDetector(sys.argv[1])
    results = detector.run()
    print(f"Intent Spoofing 취약 후보: {len(results)}건\n")
    for r in results:
        print(json.dumps(r.__dict__, indent=2, ensure_ascii=False))
