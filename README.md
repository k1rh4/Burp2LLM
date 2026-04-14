# Burp2LLM

Burp Suite에서 캡처한 HTTP 패킷을 수집하고 LLM으로 분석하는 도구.

## 구조

```
Burp2LLM/
├── docker-compose.yml          # 통합 실행
├── BurpExtention/
│   ├── STpro_hash.py           # Burp Suite 확장 (Jython)
│   └── jython-standalone-2.7.3.jar
├── CollectServer/
│   ├── Dockerfile
│   ├── docker-compose.yml      # 단독 실행용
│   ├── server.py               # 패킷 수집 서버 (FastAPI, :8888)
│   └── packets/                # 수집된 패킷 저장
└── LLMAgent/
    ├── Dockerfile
    ├── docker-compose.yml      # 단독 실행용
    ├── agent.py                # LLM 분석 에이전트 (CLI)
    └── .env.example
```

## 흐름

```
Burp Suite  ──(HTTP)──>  CollectServer(:8888)  ──(파일 저장)──>  /data/packets/
                                                                       │
                                                                       ▼
                         LLMAgent(CLI)  <──(읽기)──────────────  *.json 패킷들
                              │
                              ▼
                         LiteLLM Server(:4000)  ──>  LLM 분석 결과
```

## 사전 요구사항

- Docker & Docker Compose
- Burp Suite (Community/Professional)
- LiteLLM 서버 (호스트에서 별도 실행)

## 설정

루트 `docker-compose.yml`의 environment 섹션을 수정:

```yaml
environment:
  - LITELLM_BASE_URL=http://host.docker.internal:4000  # LiteLLM 서버 주소
  - LITELLM_API_KEY=AAAAAAAAAAAAAAAAAA                  # ← 실제 API 키로 변경
  - LITELLM_MODEL=gpt-4o                                # 사용할 모델명
  - PACKET_DIR=/data/packets                            # 패킷 저장 경로 (변경 불필요)
  - MAX_PACKETS_PER_CHUNK=20                             # 한번에 LLM에 전달할 패킷 수
```

| 변수 | 설명 | 비고 |
|---|---|---|
| `LITELLM_BASE_URL` | LiteLLM 서버 주소 | Docker 내부에서 호스트 접근 시 `host.docker.internal` 사용 |
| `LITELLM_API_KEY` | LiteLLM API 키 | 반드시 실제 키로 변경 |
| `LITELLM_MODEL` | LLM 모델명 | LiteLLM에 등록된 모델명과 일치해야 함 |
| `MAX_PACKETS_PER_CHUNK` | 청크 크기 | 토큰 제한에 맞춰 조절 |

## Docker 실행

### 1. 전체 실행 (CollectServer + LLMAgent)

```bash
# 빌드 및 백그라운드 실행
docker compose up -d --build

# 로그 확인
docker compose logs -f
```

### 2. CollectServer만 실행

패킷 수집만 먼저 시작할 때:

```bash
docker compose up -d --build collect-server
```

### 3. LLMAgent 인터랙티브 실행

수집된 패킷을 분석할 때 (인터랙티브 모드):

```bash
docker compose run llm-agent
```

### 4. 개별 디렉토리에서 단독 실행

```bash
# CollectServer 단독
cd CollectServer
docker compose up -d --build

# LLMAgent 단독 (패킷 디렉토리를 직접 마운트)
cd LLMAgent
docker compose up --build
```

### 5. 컨테이너 중지 및 정리

```bash
# 중지
docker compose down

# 중지 + 수집된 패킷 데이터까지 삭제
docker compose down -v
```

## 사용법

### Step 1: Burp Suite 확장 설치

#### 1-1. Jython 설정

Burp Suite에서 Python 확장을 사용하려면 Jython JAR 파일을 먼저 등록해야 합니다.

1. Burp Suite 실행
2. 상단 메뉴 **Extensions** > **Extensions settings** 클릭
3. **Python environment** 섹션에서:
   - **Location of Jython standalone JAR file** 옆 **Select file...** 클릭
   - `BurpExtention/jython-standalone-2.7.3.jar` 파일 선택
4. 경로가 표시되면 설정 완료

> Jython JAR 파일은 `BurpExtention/` 디렉토리에 포함되어 있으므로 별도 다운로드 불필요

#### 1-2. 확장 플러그인 추가

1. 상단 메뉴 **Extensions** > **Installed** 탭
2. **Add** 버튼 클릭
3. 다음과 같이 설정:
   - **Extension type**: `Python`
   - **Extension file (.py)**: **Select file...** 클릭 후 `BurpExtention/STpro_hash.py` 선택
4. **Next** 클릭
5. Output 탭에 아래 메시지가 출력되면 설치 성공:
   ```
   [*] Request/Response Forwarder loaded
   [*] Forwarding to 127.0.0.1:8888
   ```

> 확장이 정상 로드되면 Installed 목록에 **Request/Response Forwarder**가 체크된 상태로 나타납니다.
> 체크를 해제하면 일시 중지, 삭제하려면 **Remove** 클릭.

#### 1-3. 동작 확인

1. CollectServer가 실행 중인지 확인 (`curl http://127.0.0.1:8888/stats`)
2. Burp Suite Proxy를 통해 아무 웹사이트 탐색
3. Burp Suite의 **Extensions** > **Output** 탭에서 패킷 전송 로그 확인:
   ```
   [*] Forwarded -> GET /api/v1/users (HTTP 200)
   ```
4. CollectServer stats에서 `total_saved` 증가 확인

### Step 2: CollectServer 실행 확인

```bash
# 서버 상태 확인
curl http://127.0.0.1:8888/stats

# 응답 예시
# {"total_saved": 42, "queue_pending": 0, "current_seq": 42}
```

### Step 3: Burp Suite로 웹 탐색

Burp Suite Proxy를 통해 웹사이트를 탐색하면 자동으로 패킷이 수집됩니다.
- 같은 `METHOD + PATH` 조합은 한번만 전송 (중복 제거)
- 파일 업로드 등 큰 body는 LLMAgent에서 자동으로 플레이스홀더 처리

### Step 4: LLMAgent로 분석

```bash
docker compose run llm-agent
```

#### 명령어

| 명령어 | 설명 |
|---|---|
| (자유 입력) | LLM에 질문 (한국어/영어 모두 가능) |
| `/next` | 다음 패킷 묶음 로드 |
| `/prev` | 이전 패킷 묶음 로드 |
| `/jump <n>` | 패킷 #n 위치로 이동 |
| `/list` | 전체 패킷 목록 출력 |
| `/reload` | 디스크에서 패킷 다시 로드 (탐색 중 추가된 패킷 반영) |
| `/reset` | 대화 이력 초기화 |
| `/quit` | 종료 |

#### 질문 예시

```
You> 이 API의 인증 방식을 분석해줘
You> SQL Injection 가능성이 있는 엔드포인트를 찾아줘
You> 민감한 정보가 노출되는 응답이 있어?
You> IDOR 취약점이 있을만한 곳을 찾아줘
You> 전체 API 구조를 정리해줘
```

## 패킷 데이터

### 저장 형식

패킷은 `00000001_1713100000000.json` 형태로 저장됩니다 (시퀀스\_타임스탬프).

```json
{
  "method": "POST",
  "path": "/api/v1/login",
  "host": "example.com",
  "port": 443,
  "protocol": "https",
  "request": {
    "headers": ["POST /api/v1/login HTTP/1.1", "Host: example.com", "..."],
    "body": "{\"username\": \"admin\", \"password\": \"test\"}"
  },
  "response": {
    "status_code": 200,
    "headers": ["HTTP/1.1 200 OK", "..."],
    "body": "{\"token\": \"eyJ...\"}"
  }
}
```

### 대용량 데이터 처리

LLMAgent는 토큰 절약을 위해 500자 이상의 값을 자동으로 플레이스홀더로 대체합니다:

```
"file_content": "[LARGE_DATA:base64, 152.3KB]"
"html_page":    "[LARGE_DATA:html, 45.2KB]"
"raw_data":     "[LARGE_DATA:binary, 2.1MB]"
```

### 데이터 볼륨

두 서비스는 Docker named volume(`packet-data`)을 공유합니다:

| 서비스 | 마운트 | 모드 |
|---|---|---|
| collect-server | `/data/packets` | 읽기/쓰기 |
| llm-agent | `/data/packets` | 읽기 전용 |
