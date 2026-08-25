"""
core/scope_filter.py

앱 자체 코드가 아닌 서드파티 SDK/라이브러리 코드는 기본적으로 탐지 대상에서 제외한다.

근거: 오늘 발견된 오탐 2건(GoogleCloudMessaging, InstanceIDListenerService)이
모두 com.google.android.gms.* (Google Play Services) 패키지 안에 있었음.
이런 서드파티 SDK 내부 코드는:
  1) 앱 개발자가 직접 작성한 공격 표면이 아니고
  2) SDK 자체의 정상적인 내부 배관(plumbing)일 가능성이 높으며
  3) 이미 별도로 보안 검토를 받은 (혹은 별도 팀 소관인) 코드라서
우리 도구의 1차 탐지 대상에서는 빼는 것이 실용적이다.

주의: 이 필터는 기본값(exclude_third_party=True)이며, 완전히 끌 수도 있다.
공급망 취약점(서드파티 SDK 자체의 취약점)을 조사하고 싶을 때는
method_level_candidates(..., exclude_third_party=False) 로 끄면 된다.
"""

# smali 클래스명(L로 시작) 기준 prefix. 필요시 팀 판단으로 추가/삭제.
DEFAULT_EXCLUDE_PREFIXES = [
    "Lcom/google/android/gms/",   # Google Play Services
    "Lcom/google/firebase/",       # Firebase SDK
    "Landroid/support/",           # 구 Android Support Library
    "Landroidx/",                  # AndroidX
    "Lkotlin/",                    # Kotlin 표준 라이브러리
    "Lkotlinx/",
    "Lcom/squareup/",               # OkHttp, Retrofit 등 흔한 서드파티
    "Lokhttp3/",
    "Lretrofit2/",
    "Lnet/gotev/",                   # android-upload-service (흔히 쓰이는 서드파티 라이브러리)
]


def is_third_party(class_name: str, exclude_prefixes: list[str] | None = None) -> bool:
    """class_name(smali 형식, 예: 'Lcom/google/android/gms/gcm/GoogleCloudMessaging;')이
    서드파티 라이브러리 네임스페이스에 속하는지 판정."""
    prefixes = exclude_prefixes if exclude_prefixes is not None else DEFAULT_EXCLUDE_PREFIXES
    return any(class_name.startswith(p) for p in prefixes)


# "this.method()" 형태의 자기자신 호출이 실제로 발생하는 프레임워크 베이스 클래스.
# 앱의 Activity/Service/BroadcastReceiver 서브클래스가 이 클래스들의 메소드를
# 상속받아 호출하면, DEX 상 호출 대상 클래스가 이 베이스 클래스가 아니라
# 그 서브클래스 자신으로 찍히는 경우가 흔하다 (find_calls_by_name 으로 보강 필요).
#
# 반대로 WebView, Bundle, FileOutputStream, Runtime 같은 클래스는 앱 코드가
# 그걸 상속해서 "this.loadUrl()"처럼 호출하는 경우가 사실상 없으므로,
# 이 목록에 넣지 않는다 - 넣으면 이름만으로 찾다가 무관한 동명 메소드와
# 충돌해서 새 오탐이 생긴다 (예: Bundle.getString vs JSONObject.getString).
SELF_INVOCABLE_BASE_CLASSES = {
    "Landroid/app/Activity;",
    "Landroid/app/Service;",
    "Landroid/content/Context;",
    "Landroid/content/ContextWrapper;",
    "Landroid/content/BroadcastReceiver;",
    "Landroidx/appcompat/app/AppCompatActivity;",
    "Landroidx/fragment/app/FragmentActivity;",
}


def is_self_invocable(class_name: str) -> bool:
    """이 클래스의 메소드가 앱 서브클래스에서 'this.method()' 형태로 흔히
    호출되어, DEX 호출 대상 클래스가 서브클래스로 찍힐 위험이 있는지 판정."""
    return class_name in SELF_INVOCABLE_BASE_CLASSES
