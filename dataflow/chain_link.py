"""
dataflow/chain_link.py

2-hop Intent 체인 추적: 한 메소드(발신 메소드)가 새 Intent를 만들어 특정
컴포넌트로 전달하면서 extra 값에 외부에서 받은 값을 그대로 담아 보내고,
그 대상 컴포넌트(수신 메소드)가 같은 key로 그 값을 다시 꺼내 위험한 sink로
쓰는 2단계 패턴을 찾는다.

실제 사례 (InsecureShop): CustomReceiver.onReceive() 가 "url" extra에 값을
담아 WebView2Activity로 startActivity() -> WebView2Activity.onCreate() 가
"url" extra를 다시 꺼내 loadUrl(). 각 메소드를 따로 보면 둘 다 "정상적인
Intent 처리"처럼 보이지만, 두 메소드를 이어보면 하나의 Injection 체인이다.

FlowDroid 없이, register_link.py 와 같은 방식(명령어 텍스트 파싱, 단순
레지스터/상수 추적)을 "메소드 간"으로 한 단계 확장한 것. 정밀한 taint 분석이
아니라 휴리스틱이므로, 같은 한계(필드 저장/StringBuilder 조합을 거치면 놓침)를
그대로 안고 있다.
"""

import re
from dataclasses import dataclass, field

PUTEXTRA_TARGET = "->putExtra(Ljava/lang/String;"
NEW_INTENT_CTOR_TARGET = "Landroid/content/Intent;-><init>(Landroid/content/Context; Ljava/lang/Class;)V"
START_TARGETS = ("->startActivity(", "->startService(", "->sendBroadcast(")

GET_STRING_EXTRA_TARGET = "Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;"
BUNDLE_GET_STRING_TARGET = "Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;"


@dataclass
class ForwardedExtra:
    caller_class: str
    caller_method: str
    caller_descriptor: str
    target_class: str
    key: str
    sink_call: str  # startActivity 등, 어떤 방식으로 넘겼는지


@dataclass
class ChainFinding:
    hop1: ForwardedExtra
    hop2_class: str
    hop2_method: str
    hop2_descriptor: str
    matched_sinks: list[str] = field(default_factory=list)


def _registers(output: str) -> list[int]:
    tokens = [t.strip() for t in output.split(",")]
    return [int(t[1:]) for t in tokens if re.fullmatch(r"v\d+", t)]


def _string_literal(output: str) -> str | None:
    """const-string vN, "literal" 형태에서 literal을 뽑는다."""
    m = re.search(r'"((?:[^"\\]|\\.)*)"', output)
    return m.group(1) if m else None


def find_forwarded_extras(instructions: list) -> list[dict]:
    """
    메소드 하나의 instructions 안에서 '새 Intent 생성 -> putExtra -> start*'
    패턴을 찾는다. 반환값은 {target_class, key, sink_call} 딕셔너리 리스트
    (이 메소드 소속 정보는 호출부에서 채운다).
    """
    class_of_reg: dict[int, str] = {}     # const-class 로 얻은 레지스터->클래스
    string_of_reg: dict[int, str] = {}    # const-string 으로 얻은 레지스터->문자열
    intent_target_class: dict[int, str] = {}  # Intent 인스턴스 레지스터 -> 대상 클래스
    pending_extras: dict[int, list[tuple[str, int]]] = {}  # Intent 레지스터 -> [(key, value_reg), ...]

    results: list[dict] = []

    for i, ins in enumerate(instructions):
        name = ins.get_name()
        output = ins.get_output()

        if name == "const-class":
            regs = _registers(output)
            m = re.search(r"(L[\w/$]+;)", output)
            if regs and m:
                class_of_reg[regs[0]] = m.group(1)
            continue

        if name == "const-string" or name == "const-string/jumbo":
            regs = _registers(output)
            lit = _string_literal(output)
            if regs and lit is not None:
                string_of_reg[regs[0]] = lit
            continue

        if name.startswith("invoke"):
            if NEW_INTENT_CTOR_TARGET in output:
                regs = _registers(output)
                # regs = [instance, context, class] (Intent 생성자 순서)
                if len(regs) >= 3:
                    inst_reg, cls_reg = regs[0], regs[2]
                    target_cls = class_of_reg.get(cls_reg)
                    if target_cls:
                        intent_target_class[inst_reg] = target_cls
                        pending_extras[inst_reg] = []
                continue

            if PUTEXTRA_TARGET in output:
                regs = _registers(output)
                # regs = [intent_instance, key_reg, value_reg, ...]
                if len(regs) >= 2 and regs[0] in intent_target_class:
                    key_reg = regs[1]
                    key = string_of_reg.get(key_reg)
                    value_reg = regs[2] if len(regs) >= 3 else None
                    if key is not None:
                        pending_extras[regs[0]].append((key, value_reg))
                continue

            if any(t in output for t in START_TARGETS):
                regs = _registers(output)
                for r in regs:
                    if r in intent_target_class and pending_extras.get(r):
                        target_cls = intent_target_class[r]
                        sink_name = next(t.strip("->(") for t in START_TARGETS if t in output)
                        for key, _value_reg in pending_extras[r]:
                            results.append(
                                {"target_class": target_cls, "key": key, "sink_call": sink_name}
                            )
                continue

    return results


def find_key_extraction_with_sink(
    instructions: list, key: str, sink_entries: list[dict]
) -> list[str]:
    """
    메소드 안에서 주어진 key로 getStringExtra/Bundle.getString 을 호출하는지 찾고,
    그런 지점이 있다면 이 메소드에 매칭되는 sink(injection.yaml sinks 등)가
    있는지 함께 확인한다. 매칭된 sink 이름 리스트를 반환 (없으면 빈 리스트).
    """
    string_of_reg: dict[int, str] = {}
    key_matched = False

    for ins in instructions:
        name = ins.get_name()
        output = ins.get_output()

        if name == "const-string" or name == "const-string/jumbo":
            regs = _registers(output)
            lit = _string_literal(output)
            if regs and lit is not None:
                string_of_reg[regs[0]] = lit
            continue

        if name.startswith("invoke") and (
            GET_STRING_EXTRA_TARGET in output or BUNDLE_GET_STRING_TARGET in output
        ):
            regs = _registers(output)
            if len(regs) >= 2:
                key_reg = regs[1]
                if string_of_reg.get(key_reg) == key:
                    key_matched = True

    if not key_matched:
        return []

    matched_sinks = []
    for entry in sink_entries:
        target = f"{entry['class']}->{entry['method']}("
        for ins in instructions:
            if ins.get_name().startswith("invoke") and target in ins.get_output():
                matched_sinks.append(f"{entry['class']}#{entry['method']}")
                break
    return matched_sinks


def find_chains(locator, sink_entries: list[dict]) -> list[ChainFinding]:
    """앱 전체를 스캔해서 2-hop 체인을 찾는다."""
    findings: list[ChainFinding] = []

    for meth in locator.analysis.get_methods():
        if meth.is_external():
            continue
        enc = meth.get_method()
        if enc is None:
            continue
        try:
            instructions = list(enc.get_instructions())
        except Exception:
            continue

        forwarded = find_forwarded_extras(instructions)
        if not forwarded:
            continue

        for fwd in forwarded:
            hop1 = ForwardedExtra(
                caller_class=meth.get_class_name(),
                caller_method=meth.name,
                caller_descriptor=meth.descriptor,
                target_class=fwd["target_class"],
                key=fwd["key"],
                sink_call=fwd["sink_call"],
            )

            target_cls_analysis = locator.analysis.get_class_analysis(fwd["target_class"])
            if target_cls_analysis is None:
                continue

            for hop2_meth in target_cls_analysis.get_methods():
                hop2_enc = hop2_meth.get_method()
                if hop2_enc is None:
                    continue
                try:
                    hop2_instructions = list(hop2_enc.get_instructions())
                except Exception:
                    continue

                matched_sinks = find_key_extraction_with_sink(
                    hop2_instructions, fwd["key"], sink_entries
                )
                if matched_sinks:
                    findings.append(
                        ChainFinding(
                            hop1=hop1,
                            hop2_class=fwd["target_class"],
                            hop2_method=hop2_meth.name,
                            hop2_descriptor=hop2_meth.descriptor,
                            matched_sinks=matched_sinks,
                        )
                    )
    return findings
