"""
모듈 1: Manifest Parser
AndroidManifest.xml에서 exported 컴포넌트, permission, intent-filter 정보를 추출한다.
이 결과는 이후 모든 탐지 모듈(Spoofing / Injection / Redirection)의 공통 입력이 된다.
"""

from dataclasses import dataclass, field
from androguard.core.apk import APK
from core.log_config import silence_androguard

silence_androguard()


@dataclass
class ComponentInfo:
    name: str                      # 정규화된 클래스명 (예: com.example.app.MainActivity)
    comp_type: str                 # "activity" | "service" | "receiver" | "provider"
    exported: bool
    permission: str | None
    has_intent_filter: bool
    intent_actions: list[str] = field(default_factory=list)

    @property
    def is_publicly_reachable(self) -> bool:
        """
        실질적으로 외부에서 도달 가능한 컴포넌트인지 판정.
        intent-filter가 있으면 android:exported 를 명시하지 않아도
        암묵적으로 exported 상태가 되는 경우가 많다는 점을 반영.
        (지난 조사에서 확인된 공통 패턴)
        """
        return self.exported or (self.has_intent_filter and self.permission is None)


class ManifestParser:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = APK(apk_path)

    def _extract_intent_filters(self, comp_name: str, comp_type: str) -> tuple[bool, list[str]]:
        """androguard의 get_intent_filters()로 해당 컴포넌트의 action 목록을 뽑는다."""
        try:
            filters = self.apk.get_intent_filters(comp_type, comp_name)
        except Exception:
            return False, []
        actions = filters.get("action", []) if filters else []
        return bool(actions), actions

    def _collect(self, names: list[str], comp_type: str) -> list[ComponentInfo]:
        results = []
        for name in names:
            exported = self.apk.get_attribute_value(comp_type, "exported", name=name)
            permission = self.apk.get_attribute_value(comp_type, "permission", name=name)
            has_filter, actions = self._extract_intent_filters(name, comp_type)

            # exported 속성이 명시 안 된 경우 androguard는 None을 반환할 수 있음 -> False 취급 후
            # has_intent_filter 로 실질 노출 여부를 별도 판정 (is_publicly_reachable)
            exported_bool = str(exported).lower() == "true"

            results.append(
                ComponentInfo(
                    name=name,
                    comp_type=comp_type,
                    exported=exported_bool,
                    permission=permission,
                    has_intent_filter=has_filter,
                    intent_actions=actions,
                )
            )
        return results

    def get_public_components(self) -> dict[str, list[ComponentInfo]]:
        """네 가지 컴포넌트 타입 전체에 대해 공개(도달 가능) 여부까지 판정해서 반환."""
        raw = {
            "activity": self.apk.get_activities(),
            "service": self.apk.get_services(),
            "receiver": self.apk.get_receivers(),
            "provider": self.apk.get_providers(),
        }
        parsed = {k: self._collect(v, k) for k, v in raw.items()}
        return parsed

    def summary(self) -> dict:
        components = self.get_public_components()
        public_only = {
            k: [c for c in v if c.is_publicly_reachable]
            for k, v in components.items()
        }
        return {
            "package": self.apk.get_package(),
            "total_components": {k: len(v) for k, v in components.items()},
            "publicly_reachable": {k: [c.name for c in v] for k, v in public_only.items()},
            "components": components,
        }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("사용법: python manifest_parser.py <apk_path>")
        sys.exit(1)

    parser = ManifestParser(sys.argv[1])
    result = parser.summary()
    print(json.dumps(
        {
            "package": result["package"],
            "total_components": result["total_components"],
            "publicly_reachable": result["publicly_reachable"],
        },
        indent=2,
        ensure_ascii=False,
    ))
