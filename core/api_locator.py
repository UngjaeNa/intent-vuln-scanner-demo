"""
모듈 2: API Locator (Sink Locator)
rules/*.yaml 에 정의된 source/sink/validator 메소드 목록을 받아,
Androguard의 Analysis(XREF)로 앱 코드 전체에서 실제 호출 지점을 찾는다.

Androguard의 한계: "누가 이 메소드를 호출했는가(XREF)"까지는 알려주지만
"그 인자 값이 어디서 왔는가(taint)"는 알려주지 않는다.
그 부분은 dataflow/heuristic.py 에서 보강한다.
"""

from dataclasses import dataclass
from androguard.misc import AnalyzeAPK
from core.log_config import silence_androguard

silence_androguard()


@dataclass
class CallSite:
    api_class: str          # 호출된 API의 클래스 (예: Landroid/content/Context;)
    api_method: str          # 호출된 API의 메소드명
    caller_class: str        # 호출한 쪽의 클래스
    caller_method: str        # 호출한 쪽의 메소드명
    caller_descriptor: str    # 호출한 쪽 메소드의 디스크립터 (오버로드 구분용 - 중요!)
    offset: int               # 명령어 오프셋 (코드 위치 특정용)


class ApiLocator:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        # AnalyzeAPK가 내부적으로 create_xref()까지 수행해줌
        self.apk_obj, self.dex_list, self.analysis = AnalyzeAPK(apk_path)

    def find_calls(self, class_name: str, method_name: str) -> list[CallSite]:
        """
        특정 API(class_name.method_name)가 코드 어디서 호출되는지 XREF로 찾는다.
        class_name 은 스마일 표기(예: 'Landroid/content/Context;') 형식을 기대한다.

        주의: 이 방식은 "호출 명령어의 대상 클래스가 class_name과 정확히 일치할 때만"
        찾아낸다. 그런데 DEX 컴파일 결과, this.startActivity(...) 처럼 자기 자신이
        상속받은 메소드를 호출하면 대상 클래스가 실제 선언 클래스(Landroid/app/Activity;)가
        아니라 호출부의 서브클래스 자신으로 찍히는 경우가 흔하다 (실제 InsecureBankv2,
        InsecureShop 두 앱 모두에서 확인됨). 이런 "자기자신 호출" 패턴을 놓치지 않으려면
        find_calls_by_name() 을 대신 쓰거나 병행해야 한다.
        """
        results: list[CallSite] = []

        method_analysis = self.analysis.get_method_analysis_by_name(
            class_name, method_name, None
        )
        # descriptor를 모르거나 오버로드가 여러 개인 경우, 클래스 내 메소드를 전수 탐색
        if method_analysis is None:
            results.extend(self._search_by_class_and_name(class_name, method_name))
            return results

        for _, call, offset in method_analysis.get_xref_from():
            results.append(
                CallSite(
                    api_class=class_name,
                    api_method=method_name,
                    caller_class=call.get_class_name(),
                    caller_method=call.name,
                    caller_descriptor=call.descriptor,
                    offset=offset,
                )
            )
        return results

    def find_calls_by_name(
        self, method_name: str, descriptor_suffix: str | None = None
    ) -> list[CallSite]:
        """
        클래스명에 의존하지 않고, 앱 전체 코드에서 메소드 호출 명령어의 출력 문자열에
        '->method_name(' 이 포함된 모든 지점을 찾는다 (descriptor_suffix가 주어지면
        그 부분까지 포함해서 매칭 - 오버로드 구분용).

        find_calls() 가 놓치는 "자기자신을 통한 상속 메소드 호출" (예: this.startActivity(),
        this.sendBroadcast(), this.getCallingPackage())을 잡기 위한 보강 경로.
        Android 프레임워크 API 이름은 대부분 고유해서 이름만으로 찾아도 오탐 위험이 낮다.
        """
        results: list[CallSite] = []
        target = f"->{method_name}("
        if descriptor_suffix:
            target = f"->{method_name}({descriptor_suffix}"

        for meth in self.analysis.get_methods():
            if meth.is_external():
                continue
            enc = meth.get_method()
            if enc is None:
                continue
            try:
                instructions = enc.get_instructions()
            except Exception:
                continue
            for ins in instructions:
                if not ins.get_name().startswith("invoke"):
                    continue
                output = ins.get_output()
                if target not in output:
                    continue
                # 호출 대상의 실제 클래스(레퍼런스에 찍힌 것)도 함께 기록해두면 디버깅에 유용
                results.append(
                    CallSite(
                        api_class=output.split(target)[0].split(",")[-1].strip() or "?",
                        api_method=method_name,
                        caller_class=meth.get_class_name(),
                        caller_method=meth.name,
                        caller_descriptor=meth.descriptor,
                        offset=0,
                    )
                )
        return results

    def _search_by_class_and_name(self, class_name: str, method_name: str) -> list[CallSite]:
        """descriptor 없이 이름만으로 오버로드 전체를 찾는 보강 경로."""
        results: list[CallSite] = []
        cls = self.analysis.get_class_analysis(class_name)
        if cls is None:
            return results
        for meth in cls.get_methods():
            if meth.name == method_name:
                for _, call, offset in meth.get_xref_from():
                    results.append(
                        CallSite(
                            api_class=class_name,
                            api_method=method_name,
                            caller_class=call.get_class_name(),
                            caller_method=call.name,
                            caller_descriptor=call.descriptor,
                            offset=offset,
                        )
                    )
        return results

    def find_all(self, api_defs: list[dict]) -> dict[str, list[CallSite]]:
        """rules/*.yaml 의 sources/sinks/validators 리스트를 통째로 넣으면
        각 API별 호출 지점을 한 번에 조회한다."""
        result = {}
        for entry in api_defs:
            key = f"{entry['class']}->{entry['method']}"
            result[key] = self.find_calls(entry["class"], entry["method"])
        return result

    def get_method_instructions(self, caller_class: str, caller_method: str, caller_descriptor: str):
        """(클래스, 메소드명, 디스크립터)로 정확한 오버로드를 찾아 instructions를 반환.
        오버로드가 여러 개인 메소드에서 잘못된 것을 집으면 register_link 등의
        후속 분석이 엉뚱한 코드를 보게 되므로 디스크립터까지 반드시 맞춰야 한다."""
        cls = self.analysis.get_class_analysis(caller_class)
        if cls is None:
            return None
        for meth in cls.get_methods():
            if meth.name == caller_method and meth.descriptor == caller_descriptor:
                enc = meth.get_method()
                if enc is None:
                    return None
                return list(enc.get_instructions())
        return None


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("사용법: python api_locator.py <apk_path>")
        sys.exit(1)

    locator = ApiLocator(sys.argv[1])
    # 빠른 동작 확인용: startActivity 호출 지점 검색
    calls = locator.find_calls("Landroid/content/Context;", "startActivity")
    print(f"startActivity 호출 지점 {len(calls)}건 발견")
    for c in calls[:10]:
        print(f"  {c.caller_class}#{c.caller_method}  (offset={c.offset})")
