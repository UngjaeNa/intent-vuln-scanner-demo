"""
core/reachability.py

Injection/Redirection 탐지기는 지금까지 "코드 패턴이 있는가"만 확인하고
"그 클래스가 실제로 외부에서 도달 가능한가"는 확인하지 않았다. 그 결과
non-exported 클래스의 코드 패턴도 exported 클래스와 똑같이 "Intent 취약점"
으로 보고되는 문제가 있었다 (실제 사례: InsecureShop의 PrivateActivity -
exported는 아니지만 WebView2Activity의 Redirection 취약점을 거치면
간접적으로 도달 가능한데, 지금까지는 이 맥락 없이 독립된 발견처럼 보고됨).

이 모듈은 세 단계로 도달가능성을 판정한다.
  1. direct  : 그 클래스 자체가 exported (매니페스트 정적 선언 또는 동적 registerReceiver)
  2. chain   : exported는 아니지만, 2-hop 체인 분석(chain_link.py)에서 특정
               exported 컴포넌트가 이 클래스를 명시적 대상(new Intent + const-class)으로
               지정해 호출하는 경로가 확인됨 - 증거가 있는 구체적 경로
  3. unknown : 위 둘 다 아님 - 정적으로 확인된 도달 경로가 없음. 앱에 일반적인
               Redirection 취약점(공격자가 대상을 완전히 임의로 지정 가능한 경우)이
               있으면 "이론적으로는 그 취약점을 통해 도달 가능할 수 있으나, 특정
               경로가 증명되지는 않았다"는 참고 메모만 남긴다 (과장 방지).
"""

from dataclasses import dataclass
from core.manifest_parser import ManifestParser
from core.dynamic_receiver import find_dynamic_receivers
from core.rule_loader import to_smali_class


@dataclass
class ReachabilityInfo:
    level: str   # "direct" | "chain" | "unknown"
    note: str


class ReachabilityIndex:
    """앱 하나에 대해 한 번만 계산해두고, 여러 클래스를 반복 조회할 때 재사용."""

    def __init__(self, apk_path: str, locator, chain_findings: list | None = None):
        manifest = ManifestParser(apk_path)
        components = manifest.get_public_components()

        self.direct_classes: set[str] = set()
        for comp_list in components.values():
            for c in comp_list:
                if c.is_publicly_reachable:
                    self.direct_classes.add(to_smali_class(c.name))

        for dyn in find_dynamic_receivers(locator):
            if dyn.exposure in ("exported", "unknown"):
                self.direct_classes.add(dyn.name)

        # chain 대상: chain_link 가 찾은 hop2 클래스 (구체적 클래스명이 명시된 경로)
        # chain_findings 는 detectors/chain.py 의 ChainVulnFinding 리스트를 기대한다
        # (hop2_location 형식: "Lcom/x/Y;#method(descriptor)")
        self.chain_targets: dict[str, str] = {}
        for cf in (chain_findings or []):
            hop2_class = cf.hop2_location.split("#", 1)[0]
            self.chain_targets[hop2_class] = (
                f"{cf.hop1_location} 가 key='{cf.key}' 로 "
                f"이 클래스를 명시적으로 호출 (해당 클래스는 자체적으로는 exported가 아님)"
            )

        # 앱에 "완전히 임의 대상 지정 가능한" 일반 Redirection 취약점이 있는지
        # (type_confirmed=true 인 Redirection 발견이 있으면 그렇다고 간주 - 참고 메모용)
        self.has_generic_redirection = False  # detectors 쪽에서 필요시 set

    def classify(self, class_name: str) -> ReachabilityInfo:
        if class_name in self.direct_classes:
            return ReachabilityInfo(level="direct", note="이 클래스 자체가 exported 상태")

        if class_name in self.chain_targets:
            return ReachabilityInfo(level="chain", note=self.chain_targets[class_name])

        note = "정적으로 확인된 외부 도달 경로 없음 - 이 자체로는 Intent 기반 공격 표면이라 보기 어려움"
        if self.has_generic_redirection:
            note += (" (다만 앱 내 다른 Redirection 취약점이 임의 대상 지정을 허용하므로, "
                      "그 경로를 통해 간접적으로 도달 가능할 수 있음 - 특정 경로가 증명된 것은 아님)")
        return ReachabilityInfo(level="unknown", note=note)
