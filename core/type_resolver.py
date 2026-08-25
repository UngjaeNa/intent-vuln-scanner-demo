"""
core/type_resolver.py

Redirection 탐지의 핵심 보강: getParcelableExtra()는 반환 타입이 Parcelable이라
문자열/Bundle 등 다른 extra 추출과 구분이 안 된다. 실제 타입은 호출 직후
컴파일러가 삽입하는 check-cast 명령어를 보면 알 수 있다.

실제 smali 출력 형식 (androguard 4.1.4, get_output() 기준, 직접 확인함):
    invoke-virtual v4, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v6
    check-cast v5, Landroid/webkit/WebView;

패턴:
    invoke-virtual vX, Landroid/content/Intent;->getParcelableExtra(...)Landroid/os/Parcelable;
    move-result-object vY
    check-cast vY, <TARGET_TYPE>   <- 이 타입이 진짜 타입

TARGET_TYPE이 'Landroid/content/Intent;'인 경우만 Redirection 판별 대상.
"""

import re
from dataclasses import dataclass

MOVE_RESULT_RE = re.compile(r"^v(\d+)")
CHECK_CAST_RE = re.compile(r"^v(\d+),\s*(L[\w/$]+;)")
GET_PARCELABLE_SIG = "Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;"

INTENT_TYPE = "Landroid/content/Intent;"


@dataclass
class ParcelableExtraCast:
    register: int
    cast_type: str | None   # None이면 근처에 check-cast가 없어 타입을 못 밝힘
    instr_index: int

    @property
    def is_intent_type(self) -> bool:
        return self.cast_type == INTENT_TYPE


def _parse_move_result_register(output: str):
    m = MOVE_RESULT_RE.match(output.strip())
    return int(m.group(1)) if m else None


def _parse_check_cast(output: str):
    m = CHECK_CAST_RE.match(output.strip())
    if not m:
        return None
    return int(m.group(1)), m.group(2)


def find_parcelable_extra_casts(instructions: list, lookahead: int = 6) -> list[ParcelableExtraCast]:
    """
    instructions: EncodedMethod.get_instructions() 리스트 (get_name()/get_output() 필요)
    getParcelableExtra 호출마다, 반환값이 어떤 타입으로 캐스팅되는지 찾아 반환한다.
    """
    results: list[ParcelableExtraCast] = []
    n = len(instructions)

    for i, ins in enumerate(instructions):
        name = ins.get_name()
        output = ins.get_output()

        if not name.startswith("invoke-virtual"):
            continue
        if GET_PARCELABLE_SIG not in output:
            continue

        if i + 1 >= n:
            continue
        next_ins = instructions[i + 1]
        if next_ins.get_name() != "move-result-object":
            continue

        reg = _parse_move_result_register(next_ins.get_output())
        if reg is None:
            continue

        cast_type = None
        for j in range(i + 2, min(i + 2 + lookahead, n)):
            probe = instructions[j]
            if probe.get_name() != "check-cast":
                continue
            parsed = _parse_check_cast(probe.get_output())
            if parsed and parsed[0] == reg:
                cast_type = parsed[1]
                break

        results.append(ParcelableExtraCast(register=reg, cast_type=cast_type, instr_index=i))

    return results


def method_has_intent_typed_parcelable_extra(instructions: list) -> bool:
    """이 메소드 안에 '반환값이 실제 Intent로 캐스팅되는' getParcelableExtra 호출이 있는가."""
    return any(c.is_intent_type for c in find_parcelable_extra_casts(instructions))
