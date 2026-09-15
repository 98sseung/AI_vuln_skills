# Burp Security Review Skills

Burp Proxy HTTP History를 효율적으로 정리하고, 고위험 웹 취약점을 검증하기 위한 두 개의 스킬입니다.

## 스킬 구성

| 스킬 | 역할 |
| --- | --- |
| `burp-surface-map` | Burp History 정규화, 중복 제거, 기능 분류, 취약점 후보 선별 |
| `burp-attacker-review` | 선별된 후보의 실제 검증, WAF·필터 우회, 결과 기록 |

`surface-map`은 공격 요청을 보내지 않고 지도를 만들며, `attacker-review`가 필요한 패킷만 가져와 검증합니다.

## 권장 저장소 구조

```text
repository/
├── README.md
├── burp-surface-map/
│   └── SKILL.md
└── burp-attacker-review/
    └── SKILL.md
```

제공된 `burp-surface-map.md`, `burp-attacker-review.md`의 내용을 각각 해당 폴더의 `SKILL.md`로 사용합니다.

## 기본 사용 순서

### 1. Burp History 수집

Burp에서 대상 사이트에 로그인한 뒤 주요 메뉴를 정상적으로 탐색합니다.

### 2. 최초 공격표면 생성

```text
burp-surface-map을 사용해서 현재 Burp History의 example.com 공격표면을 최초 생성해줘.
```

엔드포인트와 취약점 후보가 다음 위치에 저장됩니다.

```text
.burp-review/<target>/state.json
```

### 3. 새로운 메뉴 탐색 후 갱신

회원·주문·결제·관리자 등 새로운 기능을 탐색한 뒤 실행합니다.

```text
burp-surface-map을 refresh 모드로 실행해서 새로 추가된 History만 반영해줘.
```

기존 History 전체를 다시 분석하지 않고 신규·변경 요청만 반영합니다.

### 4. 취약점 검증

전체 중요 후보를 검증합니다.

```text
burp-attacker-review를 all 모드로 실행해줘.
고위험 Injection과 RCE 연계 후보를 우선적으로 검증해줘.
```

필요에 따라 범위를 줄여 실행할 수 있습니다.

```text
# 특정 기능
burp-attacker-review를 feature user-management 모드로 실행해줘.

# 새로 추가된 후보
burp-attacker-review를 new 모드로 실행해줘.

# 특정 취약점 종류
burp-attacker-review를 class IDOR 모드로 실행해줘.

# 특정 후보
burp-attacker-review를 candidate cand-003 모드로 실행해줘.
```

### 5. WAF·필터 우회 검증

초기 요청이 WAF나 애플리케이션 필터에 차단된 후보에만 사용합니다.

```text
burp-attacker-review를 bypass cand-003 모드로 실행해줘.
차단 계층을 구분하고 중복되지 않는 최소 변형만 사용해서 실제 sink 도달 여부를 확인해줘.
```

GET의 `/**/` 구분자, POST Body padding, 인코딩·정규화, 파라미터 구조, Content-Type, 파서 차이 등을 후보 상황에 맞게 제한적으로 검증합니다.

단순히 WAF 응답이 달라진 것은 취약점으로 확정하지 않습니다. 변형 요청이 실제 취약 동작을 재현하고 대조 요청에서는 발생하지 않아야 `bypass-confirmed`로 판정합니다.

### 6. 점검 마무리

남은 후보를 처리합니다.

```text
burp-attacker-review를 remaining 모드로 실행해줘.
```

마지막으로 기능 간 권한·객체·가격·상태 전달 문제를 확인합니다.

```text
burp-attacker-review를 cross-feature 모드로 실행해줘.
```

## 추천 실무 루틴

```text
주요 메뉴 탐색
→ surface-map 최초 생성
→ 새로운 기능 탐색
→ surface-map refresh
→ attacker-review new 또는 feature
→ 반복
→ attacker-review remaining
→ attacker-review cross-feature
```

## 사용 시 주의사항

- `surface-map` 실행 전에는 필요한 Burp History를 삭제하지 않습니다.
- 사이트 전체를 한 번에 분석하기보다 기능 단위로 탐색하고 갱신하는 것이 효율적입니다.
- 실제 점검 권한과 범위가 확인된 대상에서만 능동 검증을 수행합니다.
- 운영 환경의 데이터 변경, 웹셸 업로드, 실제 명령 실행, 대량 요청은 별도 승인 없이 수행하지 않습니다.
- `.burp-review/`에는 점검 상태가 저장되므로 같은 프로젝트에서 이어서 사용할 때 유지합니다.
- 세션·토큰·개인정보가 Git에 포함되지 않도록 `.burp-review/`는 기본적으로 커밋하지 않는 것을 권장합니다.

`.gitignore` 예시:

```gitignore
.burp-review/
```
