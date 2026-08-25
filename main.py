"""
Intent 취약점 자동 탐지 도구 - CLI 진입점
사용법: python main.py <apk_path> [-o report.json]
"""
import sys
import argparse
import json

from core.manifest_parser import ManifestParser
from detectors.spoofing import SpoofingDetector
from detectors.redirection import RedirectionDetector
from detectors.injection import InjectionDetector
from detectors.chain import ChainDetector
from core.report_generator import generate_report, save_report


def run(apk_path: str, output: str | None):
    print(f"[*] 분석 대상: {apk_path}")
    manifest = ManifestParser(apk_path)
    package = manifest.apk.get_package()
    print(f"[*] 패키지: {package}\n")

    print("[1/4] Intent Spoofing 탐지 중...")
    spoofing = SpoofingDetector(apk_path).run()
    print(f"      -> {len(spoofing)}건 발견")

    print("[2/4] 2-hop 체인 분석 중 (도달가능성 판정에 재사용)...")
    chain_detector = ChainDetector(apk_path)
    chains = chain_detector.run()
    print(f"      -> {len(chains)}건 발견")

    print("[3/4] Intent Injection 탐지 중...")
    injection = InjectionDetector(apk_path, chain_findings=chains).run()
    print(f"      -> {len(injection)}건 발견")

    print("[4/4] Intent Redirection 탐지 중...")
    redirection = RedirectionDetector(apk_path, chain_findings=chains).run()
    print(f"      -> {len(redirection)}건 발견\n")

    report = generate_report(
        apk_path,
        package,
        {"spoofing": spoofing, "injection": injection, "redirection": redirection},
        chains=chains,
    )

    if output:
        save_report(report, output)
        print(f"[*] 리포트 저장 완료: {output}")
    else:
        print(json.dumps(report["summary"], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Intent 취약점(Spoofing/Injection/Redirection) 자동 탐지 도구")
    parser.add_argument("apk_path", help="분석할 APK 파일 경로")
    parser.add_argument("-o", "--output", help="JSON 리포트 저장 경로", default=None)
    args = parser.parse_args()

    run(args.apk_path, args.output)
