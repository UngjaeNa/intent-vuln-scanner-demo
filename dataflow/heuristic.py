"""
모듈 3-a: 경량 데이터 흐름 추적 (휴리스틱 버전)

정밀한 taint 분석(값이 정확히 어느 변수를 거쳐 흘러가는지) 대신,
"같은 메소드 안에 source 호출과 sink 호출이 함께 있고, validator 호출은 없다"는
메소드 단위 휴리스틱으로 1차 후보를 걸러낸다.

중요: 메소드 식별은 (클래스, 메소드명, 디스크립터) 3-tuple로 한다.
클래스+메소드명만으로 식별하면 오버로드(동명이인 메소드)가 섞여서
서로 무관한 메소드의 source/sink가 하나의 발견으로 잘못 합쳐지는
오탐이 발생한다 (실제 APK에서 확인된 사례: GoogleCloudMessaging 클래스에
'zza'라는 이름의 메소드가 4개 있었고, 그중 하나의 getStringExtra 호출과
전혀 다른 하나의 Bundle.putString 호출이 하나의 후보로 잘못 묶였었음).

한계:
- 레지스터 단위로 실제 값이 source->sink 로 이어지는지는 확인하지 않음 (오탐 가능)
- 메소드가 길거나 source/sink가 서로 무관한 값이어도 후보로 잡힐 수 있음
- 정밀도가 중요한 경우(특히 Injection) dataflow/flowdroid_bridge.py 로 재검증 권장
"""

from dataclasses import dataclass
from core.api_locator import ApiLocator
from core.scope_filter import is_third_party, is_self_invocable

MethodKey = tuple[str, str, str]  # (caller_class, caller_method, caller_descriptor)


@dataclass
class MethodCandidate:
    caller_class: str
    caller_method: str
    caller_descriptor: str
    matched_sources: list[str]
    matched_sinks: list[str]


def _callers_by_method(locator: ApiLocator, api_defs: list[dict]) -> dict[MethodKey, list[str]]:
    """API 리스트를 받아 {(class, method, descriptor): [매칭된 API 이름, ...]} 형태로 뒤집는다.

    클래스 기반 검색(find_calls)이 기본이다. 다만 this.startActivity(...) 처럼
    자기 자신이 상속받은 메소드를 호출하면 DEX 상 호출 대상 클래스가 실제 선언
    클래스(Landroid/app/Activity; 등)가 아니라 호출부의 서브클래스 자신으로 찍히는
    경우가 흔해서(InsecureBankv2, InsecureShop 둘 다에서 확인됨), 클래스명만으로
    찾으면 이런 "자기자신 호출"을 놓친다.

    이름 기반 보강 검색(find_calls_by_name)은 이 문제가 실제로 발생하는
    Activity/Context/Service 계열 API에만 한정해서 적용한다. WebView.loadUrl,
    Bundle.getString, FileOutputStream.write 같은 API는 앱 클래스가 그 프레임워크
    클래스를 상속하는 경우가 없어서 애초에 이 문제가 없고, 오히려 이름만으로
    찾으면 JSONObject.getString/BufferedWriter.write 처럼 이름과 디스크립터가
    우연히 같은 무관한 메소드와 충돌해서 새 오탐이 생긴다 (실제 InsecureBankv2
    DoTransfer 사례로 확인됨). 그래서 이런 API는 클래스 기반 검색만 쓴다.
    """
    mapping: dict[MethodKey, list[str]] = {}
    for entry in api_defs:
        api_label = f"{entry['class']}#{entry['method']}"

        by_class = locator.find_calls(entry["class"], entry["method"])
        by_name = []
        if is_self_invocable(entry["class"]):
            descriptor_suffix = None
            raw_descriptor = entry.get("descriptor")
            if raw_descriptor and raw_descriptor.startswith("("):
                descriptor_suffix = raw_descriptor[1:]
            by_name = locator.find_calls_by_name(entry["method"], descriptor_suffix)

        for call in by_class + by_name:
            key = (call.caller_class, call.caller_method, call.caller_descriptor)
            if api_label not in mapping.get(key, []):
                mapping.setdefault(key, []).append(api_label)
    return mapping


def method_level_candidates(
    locator: ApiLocator,
    sources: list[dict],
    sinks: list[dict],
    validators: list[dict] | None = None,
    exclude_third_party: bool = True,
) -> list[MethodCandidate]:
    """
    source 호출과 sink 호출이 동시에 존재하는 메소드를 찾는다.
    validators가 주어지면, 해당 API를 호출한 메소드는 후보에서 제외한다.
    exclude_third_party=True(기본값)면 앱 자체 코드가 아닌 서드파티 SDK
    (Google Play Services, AndroidX/Support 등) 안의 후보는 제외한다.
    """
    source_map = _callers_by_method(locator, sources)
    sink_map = _callers_by_method(locator, sinks)
    validator_map = _callers_by_method(locator, validators or [])

    candidates = []
    for key in source_map.keys() & sink_map.keys():
        if key in validator_map:
            continue
        caller_class, caller_method, caller_descriptor = key
        if exclude_third_party and is_third_party(caller_class):
            continue
        candidates.append(
            MethodCandidate(
                caller_class=caller_class,
                caller_method=caller_method,
                caller_descriptor=caller_descriptor,
                matched_sources=source_map[key],
                matched_sinks=sink_map[key],
            )
        )
    return candidates
