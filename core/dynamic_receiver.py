"""
core/dynamic_receiver.py

매니페스트에 선언되지 않고, 코드 안에서 registerReceiver()로 동적 등록되는
BroadcastReceiver를 찾는다. manifest_parser.py의 ComponentInfo와 같은 모양으로
반환해서, spoofing.py가 두 종류를 합쳐서 판정할 수 있게 한다.

registerReceiver 오버로드별 노출 여부:
  - registerReceiver(receiver, filter)                       -> 노출 (권한 없음)
  - registerReceiver(receiver, filter, permission, handler)   -> permission 필요 (보호됨)
  - registerReceiver(receiver, filter, flags)  (API 33+)      -> flags에 RECEIVER_NOT_EXPORTED
                                                                  포함 여부로 결정 (판별 어려워
                                                                  보수적으로 "확인 필요"로 표시)
"""

import re
from dataclasses import dataclass, field

REGISTER_RECEIVER_TARGET = "->registerReceiver("


@dataclass
class DynamicReceiverInfo:
    name: str                # 리시버 클래스명 (smali 형식)
    registered_in: str        # 등록을 호출한 클래스#메소드 (디버깅용)
    exposure: str              # "exported" | "protected" | "unknown"
    arg_count: int
    has_permission_arg: bool


def _registers(output: str) -> list[int]:
    tokens = [t.strip() for t in output.split(",")]
    return [int(t[1:]) for t in tokens if re.fullmatch(r"v\d+", t)]


def _param_count(output: str) -> int:
    """호출 명령어 output에서 registerReceiver(...)의 괄호 안 파라미터 개수를 센다."""
    try:
        params_part = output.split(REGISTER_RECEIVER_TARGET, 1)[1].split(")")[0]
    except IndexError:
        return 0
    if not params_part:
        return 0
    # 파라미터 사이는 공백으로 구분됨 (androguard 디스크립터 포맷)
    return len(params_part.split())


def _backtrack_receiver_class(instructions: list, call_index: int, receiver_reg: int) -> str | None:
    """registerReceiver 호출 지점(call_index)에서 거꾸로 훑어가며,
    receiver_reg에 담긴 값이 어느 클래스의 new-instance였는지 찾는다."""
    for j in range(call_index - 1, -1, -1):
        ins = instructions[j]
        if ins.get_name() != "new-instance":
            continue
        regs = _registers(ins.get_output())
        if regs and regs[0] == receiver_reg:
            # output 형태: "v0, Lcom/insecureshop/CustomReceiver;"
            parts = [p.strip() for p in ins.get_output().split(",")]
            for p in parts:
                if p.startswith("L") and p.endswith(";"):
                    return p
    return None


def find_dynamic_receivers(locator) -> list[DynamicReceiverInfo]:
    results: list[DynamicReceiverInfo] = []
    calls = locator.find_calls_by_name("registerReceiver")

    # (caller_class, caller_method, caller_descriptor) 단위로 중복 없이 메소드를 훑는다
    seen_methods = set()
    for c in calls:
        key = (c.caller_class, c.caller_method, c.caller_descriptor)
        if key in seen_methods:
            continue
        seen_methods.add(key)

        instructions = locator.get_method_instructions(*key)
        if not instructions:
            continue

        for i, ins in enumerate(instructions):
            if not ins.get_name().startswith("invoke"):
                continue
            output = ins.get_output()
            if REGISTER_RECEIVER_TARGET not in output:
                continue

            regs = _registers(output)
            param_count = _param_count(output)

            # regs[0] = 호출 인스턴스(this/context), regs[1] = receiver 인자
            receiver_reg = regs[1] if len(regs) > 1 else None
            receiver_class = (
                _backtrack_receiver_class(instructions, i, receiver_reg)
                if receiver_reg is not None
                else None
            )
            if receiver_class is None:
                continue  # 리시버 클래스를 특정 못하면 판정 불가 - 스킵

            if param_count <= 2:
                exposure = "exported"
            elif param_count >= 4:
                exposure = "protected"  # permission 인자 포함
            else:
                exposure = "unknown"  # flags 오버로드 - 수동 확인 필요 (보수적으로 별도 표시)

            results.append(
                DynamicReceiverInfo(
                    name=receiver_class,
                    registered_in=f"{c.caller_class}#{c.caller_method}",
                    exposure=exposure,
                    arg_count=param_count,
                    has_permission_arg=(param_count >= 4),
                )
            )
    return results
