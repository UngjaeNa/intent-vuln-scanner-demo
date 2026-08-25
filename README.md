# Intent 취약점 자동 탐지 도구

Android 앱의 **Intent Spoofing / Intent Injection / Intent Redirection** 세 가지 취약점을
Androguard 기반으로 자동 탐지하는 정적 분석 도구 (MVP).

## 설치

```bash
pip install -r requirements.txt --break-system-packages
```

## 사용법

```bash
python main.py <apk_path> -o report.json
```

개별 탐지기만 따로 실행하고 싶을 때:

```bash
python -m core.manifest_parser <apk_path>      # 공개 컴포넌트 목록만 확인
python -m core.api_locator <apk_path>          # startActivity 호출 지점 확인 (동작 검증용)
python -m detectors.spoofing <apk_path>
python -m detectors.injection <apk_path>
python -m detectors.redirection <apk_path>
```

## 아키텍처

```
APK
 │
 ▼
[1] Manifest Parser (core/manifest_parser.py)      — exported 컴포넌트, permission, intent-filter 추출
 │
 ▼
[2] API Locator (core/api_locator.py)              — Androguard XREF로 source/sink/validator 호출 지점 탐색
 │
 ├─ Spoofing (detectors/spoofing.py)                — 구조적 판별: exported + 검증 API 호출 부재
 │                                                      (taint 분석 불필요, Androguard만으로 처리)
 │
 ├─ Redirection (detectors/redirection.py)           — 메소드 레벨 휴리스틱:
 │                                                      Intent 추출 + 재실행 API 동시 존재 + 검증 부재
 │
 └─ Injection (detectors/injection.py)               — 메소드 레벨 휴리스틱:
                                                         외부 입력 + 위험 sink 동시 존재
                                                         (정밀도 필요시 dataflow/flowdroid_bridge.py 로 확장 예정)
 │
 ▼
[5] Report Generator (core/report_generator.py)     — CWE/MASVS 매핑, JSON 리포트 생성
```

## 규칙 파일 (rules/*.yaml)

세 취약점 각각의 source/sink/validator API 목록. FlowDroid `SourcesAndSinks.txt`,
IccTA `SourcesAndSinks.txt`, 그리고 실제 CVE 사례(CVE-2024-36062, CVE-2023-47889,
CVE-2024-26131 등) 분석을 근거로 정리했습니다. 각 파일의 `notes` 필드에 근거를 기록해뒀습니다.

## 알려진 한계 (다음 단계에서 보강할 부분)

1. **메소드 레벨 휴리스틱의 오탐 가능성**
   현재 Redirection/Injection은 "같은 메소드 안에 source와 sink가 함께 있는가"만 확인합니다.
   실제로 그 값이 source에서 sink로 흘러가는지(레지스터 단위 추적)는 확인하지 않습니다.
   → `dataflow/flowdroid_bridge.py` (미구현, TODO)로 애매한 케이스만 선택적으로 재검증하는 것을
   다음 단계로 계획하고 있습니다.

2. ~~**Redirection의 타입 판별 미구현**~~ → **구현 완료** (`core/type_resolver.py`)
   `getParcelableExtra()` 호출 직후의 `check-cast` 명령어를 파싱해, 반환값이 실제로
   `Intent` 타입인지 확인합니다. 4가지 케이스(Intent로 캐스팅 / 다른 타입으로 캐스팅 /
   캐스팅 없음 / 호출 자체 없음)에 대한 유닛 테스트로 파싱 로직을 검증했습니다.
   `Intent`가 아닌 타입으로 명확히 캐스팅되는 경우는 후보에서 제외해 오탐을 줄이고,
   check-cast로 Intent 타입까지 확인된 경우는 `severity: high`로 격상됩니다.

3. **PendingIntent 역방향 리다이렉션 미탐지**
   `PendingIntent.send()` 관련 변형 공격은 규칙에 등록만 해두고 실제 탐지 로직은 아직 없습니다.

4. **테스트 검증**: InsecureBankv2 APK로 검증한 결과
   - Spoofing: `MyBroadCastReceiver` 등 8건 탐지 (실제 알려진 취약점과 일치)
   - Injection: 오탐 검증 후 개선 중.
     아래 "오탐 감소 조치" 참고
   - Redirection: 0건 (이 앱에 프록시 패턴이 없어 합리적인 결과로 판단)

## 오탐 감소 조치 (2026-08-22 반영)

Injection 탐지 결과를 실제 디컴파일 코드로 하나씩 검증하다가 3건 중 2건이 오탐임을 발견,
원인을 분석해 세 가지를 수정했다:

1. **오버로드 병합 버그 수정** (`core/api_locator.py`, `dataflow/heuristic.py`)
   기존에는 `(클래스, 메소드명)`만으로 메소드를 식별해서, 동명이인 메소드(오버로드)의
   source/sink 호출이 서로 다른 메소드인데도 하나의 발견으로 잘못 합쳐지는 버그가 있었음.
   실제 사례: `GoogleCloudMessaging` 클래스에 `zza`라는 이름의 메소드가 4개 있었고,
   그중 하나의 `getStringExtra`와 전혀 다른 하나의 `Bundle.putString`이 섞여서 오탐 발생.
   → `(클래스, 메소드명, 디스크립터)` 3-tuple로 식별하도록 수정.

2. **Propagator를 sink에서 분리** (`rules/injection.yaml`)
   `Bundle.putString`/`putParcelable`은 "위험한 곳"이 아니라 "중간에 값을 담는 지점"인데
   sink로 등록해뒀던 게 오탐 원인이었음. `propagators` 섹션으로 분리하고 detector에서는
   더 이상 sink로 쓰지 않음 (2단계 체인 분석 도입 시 재활용 예정).

3. **서드파티 라이브러리 제외** (`core/scope_filter.py`, 신규)
   오탐 2건 모두 `com.google.android.gms.*` (Google Play Services) 안에 있었음.
   앱 개발자가 직접 작성한 코드가 아닌 SDK 내부 코드는 기본적으로 탐지 범위에서 제외
   (`method_level_candidates(..., exclude_third_party=True)`, 기본값).
   공급망 취약점을 조사하고 싶을 때는 `exclude_third_party=False`로 끌 수 있음.

## IR-Hunter 논문(ICASSP 2026) 참고 반영 (2026-08-22)

Yue Jiang 등, "IR-Hunter: Automated Analysis of Intent Redirection Vulnerabilities in
Android Applications Based on Hybrid Dynamic and Static Approaches" (ICASSP 2026) 검토 후
바로 적용 가능한 부분 반영.

### setResult sink 추가

논문 Fig.1의 대표 예시: exported 액티비티가 `getIntent()`로 받은 값을 검증 없이
그대로 `setResult()`로 돌려보내면, `startActivityForResult`로 호출한 쪽에 민감
정보가 유출될 수 있음. `rules/redirection.yaml`의 sink 목록에 `Activity.setResult`
추가 (`this.setResult(...)` 자기자신 호출 패턴 고려해 `is_self_invocable` 목록의
`Landroid/app/Activity;`를 그대로 활용).

### 부수적으로 발견한 버그: register_link.py의 자기자신 호출 미보정

`setResult` 패턴을 합성 테스트 케이스로 검증하다가, `dataflow/register_link.py`가
`dataflow/heuristic.py`에 적용했던 "자기자신 호출 클래스명 불일치" 보정을 받지
못했다는 걸 발견함 (`this.getIntent()` → `this.setResult()`처럼 두 API 모두
자기자신을 통해 호출되는 경우, 레지스터 연결 확인이 항상 조용히 실패하고
있었음). `is_self_invocable()` 기준으로 느슨한 매칭(클래스명 무관, 메소드명
기준)을 병행하도록 수정. 합성 테스트 케이스로 재현 및 수정 확인, 기존 오탐
방지 회귀 테스트도 재통과.

**효과**: InsecureShop의 `WebView2Activity` Redirection 발견에 그동안 못
잡던 "레지스터 단위로 연결까지 확인됨" 근거가 추가로 붙음 (기존엔
`type_confirmed`만으로 high였는데, 이제 실제 데이터 흐름까지 증명됨).

### 논문에서 시사받은 것 - 다음 계획에 반영 예정

- Table 1의 "Field propagation"(필드에 저장했다가 나중에 검증 후 사용) 패턴은
  이 논문이 비교 대상으로 삼은 SOTA 도구(LetterBomb)도 실패하는 것으로 보고됨 -
  우리 `register_link.py`의 알려진 한계와 동일한 지점이라, 업계에서도 어려운
  문제임을 보여주는 참고 근거로 기록
- 논문처럼 합성 테스트 케이스(12종 제약 패턴)를 만들어 우리 탐지기의 커버리지를
  체계적으로 진단하는 것을 다음 작업 후보로 고려 중

## 레지스터 단위 연결 확인 (2026-08-22 반영)

`dataflow/register_link.py`: source 호출 결과 레지스터가 move/move-object 별칭을 거쳐
sink 호출 인자로 실제 이어지는지 확인. 4가지 케이스로 유닛 테스트 검증:

| 케이스 | 결과 |
|---|---|
| 직접 연결 | 탐지됨 |
| move-object 별칭 경유 | 탐지됨 |
| 무관한 값이 sink로 감 | 정상적으로 미탐지 |
| **필드 저장(iput/iget) 경유** | **탐지 안 됨 (알려진 한계)** |

**실제 APK로 검증한 결과**: 우리가 가진 유일한 진짣 Injection 사례(`ViewStatement`)는
`getStringExtra → 필드 저장 → StringBuilder 조합 → loadUrl` 순서라 정확히 "필드 저장 경유"
패턴에 해당해서 `register_confirmed: false`로 나옴. 이 결과를 근거로 **"연결 증거가 없다고
후보를 걸러내지 않고, 있을 때만 confidence를 올리는" 설계를 채택** — 증거 부재를 필터링에
썼다면 유일한 진짜 취약점을 놓칠 뻔했음. `InjectionFinding.register_confirmed`,
`RedirectionFinding`(내부적으로 register_confirmed 사용)에 각각 반영됨.

**한계**: 필드 저장, StringBuilder 조합, 메소드 간 전달(inter-procedural)을 거치는 흐름은
추적 못함. 이 이상의 정밀도가 필요하면 FlowDroid 연동(`dataflow/flowdroid_bridge.py`,
아직 미구현)이 필요.

## 2번째 APK(InsecureShop)로 검증하며 발견한 구조적 결함 (2026-08-22 반영)

**배경**: "도구가 InsecureBankv2 한 APK에만 과적합된 게 아닌가"라는 우려로 InsecureShop.apk를
추가 검증. 실제로 심각한 구조적 결함을 발견하고 수정함.

### 1. DEX 자기자신 호출 클래스명 불일치 (가장 심각했던 버그)

`this.startActivity(...)`처럼 자기 자신이 상속받은 메소드를 호출하면, DEX 명령어의 호출
대상 클래스가 실제 선언 클래스(`Landroid/app/Activity;`)가 아니라 **호출부의 서브클래스
자신**으로 찍힌다 (InsecureBankv2, InsecureShop 두 앱 모두에서 확인된 범용적 컴파일 동작).
기존 `find_calls()`는 클래스명이 정확히 일치해야만 찾았기 때문에 이런 "자기자신 호출"을
전부 놓치고 있었음 → InsecureShop의 공식 문서화된 Redirection 취약점(`WebView2Activity`)을
탐지 실패하는 것으로 드러남.

**수정**: `core/api_locator.py`에 `find_calls_by_name()` 추가 - 클래스명에 의존하지 않고
메소드 이름(+가능하면 디스크립터)만으로 앱 전체를 스캔. `dataflow/heuristic.py`,
`detectors/spoofing.py` 모두 클래스 기반 검색과 병행하도록 수정.

### 2. 위 수정의 부작용: getIntent() 단독 co-occurrence 오탐

메소드명 기반 검색이 넓어지자, `getIntent()`가 너무 흔한 API라서 `startActivity`/
`sendBroadcast`와 그저 같은 메소드에 있기만 해도 걸리는 새 오탐이 발생
(InsecureBankv2의 `DoLogin`/`ViewStatement`, InsecureShop의 서드파티 라이브러리
`net.gotev.uploadservice.UploadTask` 4건).

**수정**: Redirection 판정에서 `getParcelableExtra`가 매칭되지 않았고 레지스터 연결
증거도 없으면 후보에서 제외하도록 필터 추가 (`getIntent()` 단독은 근거 불충분으로 간주).

### 3. 서드파티 라이브러리 목록 보강

`net/gotev/` (android-upload-service) 를 `core/scope_filter.py`의 기본 제외 목록에 추가.

### 검증 결과 (InsecureShop 공식 문서 대비)

| 탐지 결과 | 공식 문서 챌린지 |
|---|---|
| Redirection: `WebView2Activity` (type_confirmed=true) | Intent Redirection (Access to Protected Components) |
| Injection: `PrivateActivity`/`WebViewActivity`/`WebView2Activity` (전부 register_confirmed=true) | Insufficient URL Validation 등 |
| Spoofing: exported 컴포넌트 다수 + 서드파티 `UploadService` | Insecure Broadcast Receiver 계열 |

### 알려진 한계 (미해결)

`manifest_parser.py`는 AndroidManifest.xml에 선언된 컴포넌트만 본다. 코드 안에서
`registerReceiver()`를 동적으로 호출하는 패턴(InsecureShop의 "Insecure Broadcast
Receiver" 챌린지가 이 방식으로 추정됨)은 매니페스트만 봐서는 안 보여서 놓칠 수 있다.
다음 개선 대상.

## 동적 브로드캐스트 리시버 탐지 추가 (2026-08-22 반영)

**배경**: 위 한계로 InsecureShop의 "Insecure Broadcast Receiver" 챌린지(`CustomReceiver`,
`web_url` extra를 받아 검증 없이 WebView2Activity로 전달)를 놓치고 있던 것을 확인.

### 구현

`core/dynamic_receiver.py` 신규: `find_calls_by_name("registerReceiver")`로 호출 지점을
찾고, 인자 개수로 노출 여부를 판정 (2-인자=exported, 4-인자=permission 있음/protected,
3-인자 flags 오버로드=수동 확인 필요). 호출 직전 `new-instance` 명령어를 역추적해서
실제 리시버 클래스를 특정. `detectors/spoofing.py`가 매니페스트 컴포넌트 목록과 이
동적 리시버 목록을 합쳐서 같은 판정 로직(검증 API 부재 확인)을 적용하도록 통합.

**검증 결과**: InsecureShop에서 `CustomReceiver`(AboutUsActivity가 2-인자로 등록,
검증 없음)를 정확히 탐지 (Spoofing 8건→9건). InsecureBankv2는 회귀 없음(8건 유지).

**주의 - 처음엔 이것도 서드파티 오탐을 냈음**: 동적 리시버 탐지를 붙이자마자
InsecureBankv2에서 8건→12건으로 늘었는데, 새로 잡힌 4건 전부가
`android.support.v7.media.*`(AndroidX 미디어 라우터), `com.google.android.gms.*`
(Google Play Services) 같은 서드파티 라이브러리 내부 코드였음. Injection/Redirection
때 이미 겪었던 것과 동일한 패턴이라, `core/scope_filter.py`의 `is_third_party()`를
동적 리시버 판정에도 그대로 적용해서 해결 (8건→12건→**8건**으로 원복, InsecureShop은
진짜 9건 유지).

### 알려진 한계

- 리시버 인스턴스가 `new-instance` 직후 바로 등록되지 않는 패턴(예: 필드에 미리
  저장해뒀다가 나중에 등록)은 역추적이 못 찾음 - 실제로 InsecureShop의
  `ProductListActivity`가 등록한 리시버 하나는 이 이유로 놓쳤을 가능성이 있음
- 3-인자(flags) 오버로드는 `RECEIVER_NOT_EXPORTED` 여부를 정확히 판별하지 않고
  "unknown"으로만 표시 - 실제 플래그 값을 추적하는 정밀화가 다음 개선 대상
- 여전히 메소드 간(inter-procedural) 흐름은 못 봄: `CustomReceiver.onReceive`가
  값을 꺼내 새 Intent로 만들어 `WebView2Activity`로 넘기고, 거기서 `loadUrl`이
  실행되는 **2단계 공격 체인**은, 이번 수정으로도 여전히 하나의 Injection 발견으로
  잡히지 않는다 (각 클래스는 Spoofing 관점으로는 개별적으로 잡히지만, "체인"으로는
  안 보임 - FlowDroid 연동이 필요한 대표적 사례로 기록해둠)

## 2-hop 체인 추적 추가 (2026-08-22 반영)

**배경**: 위에서 기록한 "메소드 간 흐름을 못 본다"는 한계를 실제로 해결. FlowDroid
연동(Java/Soot 툴체인 신규 구축, 비용이 큼) 대신, 우선 register_link.py 방식을
메소드 간으로 확장하는 가벼운 방법으로 시도.

### 구현

`dataflow/chain_link.py`: 앱 전체 메소드를 스캔해서 두 단계를 연결한다.
- **1단계(발신)**: `new-instance Intent` → `const-class`(대상 클래스) →
  `Intent.<init>(Context, Class)` → `putExtra(key, value)` → `startActivity`/
  `startService`/`sendBroadcast` 순서의 명령어 시퀀스를 추적해 "어느 클래스로,
  어떤 key에 값을 실어 보내는지" 파악
- **2단계(수신)**: 1단계에서 찾은 대상 클래스의 모든 메소드를 훑어서, **같은 key**로
  `getStringExtra`/`getExtras().getString`을 호출하는 지점을 찾고, 그 메소드에
  `rules/injection.yaml`의 sink가 있는지 확인

`detectors/chain.py`, `main.py`(4단계로 확장), `core/report_generator.py`에 통합.
Spoofing/Injection/Redirection과 별개의 "4번째 취약점"이 아니라, 기존 세 탐지를
메소드 간으로 보강하는 **보강 분석**으로 명확히 구분해서 표시.

### 검증 결과

- **InsecureShop**: `CustomReceiver.onReceive`(key="url" 전달) →
  `WebView2Activity.onCreate`(key="url" 수신) → `WebView.loadUrl` 체인을
  정확히 1건 탐지. 처음 이 기능을 계획하게 만든 바로 그 사례를 실제로 해결.
- **InsecureBankv2**: `PostLogin#viewStatment`(key="uname") →
  `ViewStatement#onCreate` → `WebView.loadUrl` 체인 1건 탐지. 다만 이건
  **새로운 취약점이 아니라 이미 알고 있던 것의 재확인**임 - `PostLogin`은
  로그인된 사용자가 자기 내역을 보러 가는 정상적인 내부 네비게이션이고,
  진짜 문제는 여전히 `ViewStatement`가 exported라서 외부에서 임의의 uname으로
  직접 호출 가능하다는 것 (기존 Injection 탐지기가 이미 잡고 있었음). 체인
  탐지기가 존재하지 않는 취약점을 지어내지 않고 실제 흐름만 정직하게 보고한다는
  긍정적 신호로 판단.

### 알려진 한계

- register_link.py와 같은 한계(필드 저장/StringBuilder 조합을 거치면 놓침)를
  메소드 간 버전에서도 그대로 가짐 - 1단계의 값이 곧바로 putExtra에 쓰이거나,
  2단계의 값이 곧바로 sink에 쓰이는 "직접적인" 경우만 잡음
- 앱 전체 메소드를 매번 새로 스캔하기 때문에 다른 탐지기보다 느림 (두 테스트
  앱 기준 약 17초 추가) - 앱이 커지면 성능 저하 가능성, 캐싱/인덱싱 여지 있음
- 2단계 이상(3-hop 이상)의 체인은 여전히 못 봄
