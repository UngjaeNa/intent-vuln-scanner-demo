"""
dataflow/register_link.py
모듈 3-a 휴리스틱(method_level_candidates)을 한 단계 더 정밀화:
"source 호출 결과 레지스터가 실제로 sink 호출의 인자 레지스터로 쓰이는가"를 확인한다.

type_resolver.py 의 check-cast 추적 방식을 일반화한 것 - 명령어 시퀀스를
텍스트 파싱해서 레지스터 흐름을 따라간다.

추적 범위(의도적으로 보수적/단순하게 설계):
- source 호출 -> move-result(-object) 로 받은 레지스터를 시작점으로 삼음
- move / move-object 로 다른 레지스터에 그대로 복사되는 경우(별칭)만 추적
- 그 레지스터(또는 별칭)가 sink 호출의 인자로 쓰이면 "연결 확인"으로 판정

한계: 필드 저장(iput/iget)이나 StringBuilder 같은 문자열 조합을 거치는 경우는
추적하지 못한다. 즉 이 체크는 "정확한 연결"을 확인하는 데는 쓸 수 있지만,
"연결이 안 보인다고 진짜 무관하다"고 단정할 수는 없다 (미탐 위험).
그래서 detectors 에서는 이 결과를 "confidence 를 올리는 근거"로만 쓰고,
증거가 없다고 후보 자체를 걸러내지는 않는다.
"""

import re
from dataclasses import dataclass
from core.scope_filter import is_self_invocable

MOVE_ALIAS_OPS = {
    "move-object", "move", "move-object/from16", "move/from16", "move-object/16", "move/16",
}


@dataclass
class FlowEvidence:
    source_index: int
    source_sig: str
    sink_index: int
    sink_sig: str
    register: int


def _registers(output: str) -> list[int]:
    """명령어 output 문자열에서 'vN' 형태의 레지스터 토큰만 뽑는다."""
    tokens = [t.strip() for t in output.split(",")]
    return [int(t[1:]) for t in tokens if re.fullmatch(r"v\d+", t)]


def _sig_matchers(entry: dict) -> list[str]:
    """
    rule entry(class+method) -> smali 호출 문자열에서 매칭할 접두 문자열(들).

    기본은 정확한 클래스명 매칭이지만, this.getIntent()/this.startActivity()/
    this.setResult() 처럼 자기자신이 상속받은 메소드를 호출하는 경우 DEX 상
    호출 대상 클래스가 실제 선언 클래스(Landroid/app/Activity; 등)가 아니라
    호출부의 서브클래스 자신으로 찍히는 경우가 흔하다 (dataflow/heuristic.py 에서
    먼저 발견하고 고쳤던 문제와 동일 - register_link.py 에는 이 보정이 빠져 있어서
    IR-Hunter 논문의 예시(getIntent() -> setResult())를 재현하다가 뒤늦게 발견됨).

    is_self_invocable(class)면 정확한 매칭 문자열에 더해, 클래스명 무관하게
    메소드명(+디스크립터가 있으면 그것까지)으로도 매칭하는 느슨한 패턴을 추가한다.
    """
    exact = f"{entry['class']}->{entry['method']}("
    matchers = [exact]
    if is_self_invocable(entry["class"]):
        matchers.append(f"->{entry['method']}(")
    return matchers


def find_flow_evidence(
    instructions: list,
    source_entries: list[dict],
    sink_entries: list[dict],
    lookahead: int = 40,
) -> list[FlowEvidence]:
    """
    메소드 하나의 instructions 안에서, source 호출 결과가 실제로 sink 호출
    인자로 이어지는 지점을 찾는다. 발견된 모든 연결을 반환 (없으면 빈 리스트).
    """
    source_sigs = [m for e in source_entries for m in _sig_matchers(e)]
    sink_sigs = [m for e in sink_entries for m in _sig_matchers(e)]
    n = len(instructions)
    evidence: list[FlowEvidence] = []

    for i, ins in enumerate(instructions):
        name = ins.get_name()
        output = ins.get_output()
        if not name.startswith("invoke"):
            continue
        matched_source = next((s for s in source_sigs if s in output), None)
        if not matched_source:
            continue

        if i + 1 >= n:
            continue
        nxt = instructions[i + 1]
        if not nxt.get_name().startswith("move-result"):
            continue
        src_regs = _registers(nxt.get_output())
        if not src_regs:
            continue
        aliases = {src_regs[0]}

        for j in range(i + 2, min(i + 2 + lookahead, n)):
            probe = instructions[j]
            pname, poutput = probe.get_name(), probe.get_output()

            if pname in MOVE_ALIAS_OPS:
                regs = _registers(poutput)
                if len(regs) == 2:
                    dst, src = regs
                    if src in aliases:
                        aliases.add(dst)

            elif pname.startswith("invoke"):
                matched_sink = next((s for s in sink_sigs if s in poutput), None)
                if matched_sink:
                    call_regs = set(_registers(poutput))
                    if aliases & call_regs:
                        evidence.append(
                            FlowEvidence(
                                source_index=i,
                                source_sig=matched_source,
                                sink_index=j,
                                sink_sig=matched_sink,
                                register=src_regs[0],
                            )
                        )
                        break
    return evidence
