"""androguard의 기본 로그가 매우 장황해서(DEBUG 레벨) 억제하는 공통 설정."""
import logging


def silence_androguard():
    for name in ("androguard", "androguard.core", "androguard.core.apk", "androguard.core.axml"):
        logging.getLogger(name).setLevel(logging.ERROR)
