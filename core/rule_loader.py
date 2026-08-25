"""rules/*.yaml 을 읽어 파이썬 객체로 반환하는 공통 로더."""
import yaml
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent / "rules"


def load_rule(name: str) -> dict:
    """name: 'spoofing' | 'injection' | 'redirection'"""
    path = RULES_DIR / f"{name}.yaml"
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def to_smali_class(java_class_name: str) -> str:
    """'android.content.Context' -> 'Landroid/content/Context;' 형식 변환."""
    if java_class_name.startswith("L") and java_class_name.endswith(";"):
        return java_class_name  # 이미 smali 형식
    return "L" + java_class_name.replace(".", "/") + ";"
