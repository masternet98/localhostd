# 윈도우 Cloudflared 터널 관리 프로그램 개발 요청 문서

## 개요
현재 Streamlit 애플리케이션에 포함된 Cloudflared 터널 관리 기능을 **최경량 독립 윈도우 프로그램**으로 분리하여 개발합니다. **최소한의 시스템 자원**을 사용하면서 로컬 서비스를 외부 클라우드 환경에서 임시로 사용할 수 있게 하는 핵심 기능만을 제공합니다.

## 경량화 설계 원칙

### 1. **최소 리소스 사용**
- **메모리 사용량**: 50MB 이하 목표
- **CPU 사용률**: 유휴 시 1% 이하
- **디스크 용량**: 실행 파일 20MB 이하
- **네트워크**: 터널 설정 시에만 사용

### 2. **최경량 기술 스택**
- **GUI**: tkinter (Python 내장, 추가 의존성 없음)
- **패키징**: PyInstaller --onefile (단일 실행 파일)
- **의존성**: 최소한으로 제한 (qrcode 제외 고려)

## 핵심 기능 요구사항 (최소화)

### 1. **필수 터널 관리 기능**
- Cloudflared 터널 시작/중지
- 터널 상태 표시 (실행중/중지됨)
- 공개 URL 자동 감지 및 표시
- 포트 설정 (기본값: 8501)

### 2. **최소 UI 기능**
- 간단한 상태 표시
- URL 복사 기능
- 브라우저에서 열기
- **제외**: QR 코드 생성 (의존성 경량화)

### 3. **경량 로그 관리**
- 메모리 내 로그만 유지 (최대 100줄)
- 파일 저장 없음 (디스크 I/O 최소화)
- 간단한 오류 메시지만 표시

## Cloudflared 설치 및 관리 시스템

### 1. **자동 설치 감지 로직**
프로그램 시작 시 다음 순서로 cloudflared 검색:

```python
def detect_cloudflared():
    # 1. PATH 환경변수에서 검색
    if shutil.which("cloudflared"):
        return shutil.which("cloudflared")
    
    # 2. 표준 설치 경로 검색
    standard_paths = [
        r"C:\Program Files\cloudflared\cloudflared.exe",
        r"C:\Program Files (x86)\cloudflared\cloudflared.exe", 
        r"%LOCALAPPDATA%\cloudflared\cloudflared.exe",
        r"%USERPROFILE%\.cloudflared\cloudflared.exe"
    ]
    
    for path in standard_paths:
        expanded = os.path.expandvars(path)
        if os.path.isfile(expanded):
            return expanded
    
    return None  # 설치되지 않음
```

### 2. **Cloudflared 미설치 시 처리**

#### A. **안내 대화상자 표시**
```
┌─ Cloudflared 설치 필요 ─────────────────────┐
│                                            │
│  ⚠️  Cloudflared가 설치되지 않았습니다.      │
│                                            │
│  터널 기능을 사용하려면 Cloudflared를       │
│  먼저 설치해야 합니다.                     │
│                                            │
│  [자동 설치] [수동 설치 안내] [나중에]     │
└────────────────────────────────────────────┘
```

#### B. **자동 설치 기능**
```python
def auto_install_cloudflared():
    """Cloudflared 자동 다운로드 및 설치"""
    try:
        # 1. 최신 버전 확인
        download_url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        
        # 2. 사용자 로컬 디렉토리에 다운로드
        local_dir = os.path.join(os.environ['LOCALAPPDATA'], 'cloudflared')
        os.makedirs(local_dir, exist_ok=True)
        local_path = os.path.join(local_dir, 'cloudflared.exe')
        
        # 3. 진행률 표시하며 다운로드
        download_with_progress(download_url, local_path)
        
        # 4. 실행 권한 확인
        if os.path.isfile(local_path):
            return local_path
            
    except Exception as e:
        show_error(f"자동 설치 실패: {e}")
        return None
```

#### C. **수동 설치 안내**
```
┌─ Cloudflared 수동 설치 안내 ────────────────┐
│                                            │
│  📥 수동 설치 방법:                        │
│                                            │
│  1. 공식 다운로드 페이지 방문:             │
│     https://github.com/cloudflare/         │
│     cloudflared/releases                   │
│                                            │
│  2. Windows용 파일 다운로드:               │
│     cloudflared-windows-amd64.exe          │
│                                            │
│  3. 다운로드한 파일을 다음 중 한 곳에      │
│     복사:                                  │
│     • C:\Program Files\cloudflared\        │
│     • 현재 프로그램과 같은 폴더            │
│     • PATH 환경변수 등록된 폴더            │
│                                            │
│  [공식 페이지 열기] [확인]                 │
└────────────────────────────────────────────┘
```

### 3. **다운로드 진행률 UI**
```python
class DownloadProgressDialog:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Cloudflared 다운로드 중...")
        self.window.geometry("400x150")
        
        # 진행률 표시
        self.progress_label = tk.Label(self.window, text="다운로드 준비 중...")
        self.progress_bar = ttk.Progressbar(self.window, mode='determinate')
        self.cancel_btn = tk.Button(self.window, text="취소", command=self.cancel)
        
    def update_progress(self, current, total):
        percent = int((current / total) * 100)
        self.progress_bar['value'] = percent
        self.progress_label.config(text=f"다운로드 중... {percent}% ({current}/{total} bytes)")
```

### 4. **Cloudflared 버전 관리**

#### A. **버전 확인 기능**
```python
def get_cloudflared_version(cloudflared_path):
    """설치된 cloudflared 버전 확인"""
    try:
        result = subprocess.run([cloudflared_path, "--version"], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # "cloudflared version 2023.10.0" 형태에서 버전 추출
            version_match = re.search(r'version (\d+\.\d+\.\d+)', result.stdout)
            if version_match:
                return version_match.group(1)
    except Exception:
        pass
    return "알 수 없음"
```

#### B. **업데이트 확인 (선택사항)**
```python
def check_for_updates(current_version):
    """최신 버전 확인 (GitHub API 사용)"""
    try:
        import json
        import urllib.request
        
        url = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read())
            latest_version = data['tag_name'].lstrip('v')
            
        if latest_version != current_version:
            return latest_version
    except Exception:
        pass
    return None
```

### 5. **설치 상태 UI 통합**

#### A. **메인 윈도우에 상태 표시**
```
┌─ Cloudflared 터널 관리자 ─────────────────┐
│                                          │
│  Cloudflared: ✅ v2023.10.0 (정상)      │
│  상태: ● 실행중     포트: [8501]         │
│                                          │
│  URL: https://abc123.trycloudflare.com   │
│  [복사] [열기]                           │
│                                          │
│  [시작] [중지] [재설치]                  │
└──────────────────────────────────────────┘
```

#### B. **설치 상태별 UI 변경**
- **설치됨**: 정상 터널 관리 UI 표시
- **미설치**: 설치 안내 및 자동 설치 버튼만 표시
- **설치 중**: 진행률 표시 및 다른 기능 비활성화

### 6. **에러 처리 및 복구**

#### A. **일반적인 설치 오류**
```python
def handle_installation_errors():
    error_solutions = {
        "PermissionError": "관리자 권한이 필요합니다. 프로그램을 관리자 권한으로 실행해주세요.",
        "ConnectionError": "인터넷 연결을 확인해주세요. 방화벽이 다운로드를 차단할 수 있습니다.",
        "FileNotFoundError": "다운로드한 파일을 찾을 수 없습니다. 다시 시도해주세요.",
        "TimeoutError": "다운로드 시간이 초과되었습니다. 네트워크 상태를 확인해주세요."
    }
    return error_solutions
```

#### B. **설치 검증**
```python
def verify_installation(cloudflared_path):
    """설치된 cloudflared가 정상 작동하는지 확인"""
    try:
        # 간단한 help 명령으로 실행 가능성 확인
        result = subprocess.run([cloudflared_path, "--help"], 
                              capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False
```

### 7. **경량화를 위한 설치 관리 최적화**

#### A. **최소 의존성 다운로드**
- urllib.request (표준 라이브러리) 사용
- 외부 다운로드 라이브러리 배제
- 간단한 HTTP 요청만 사용

#### B. **메모리 효율적 다운로드**
```python
def download_with_progress(url, local_path, chunk_size=8192):
    """메모리 효율적인 스트리밍 다운로드"""
    import urllib.request
    
    with urllib.request.urlopen(url) as response:
        total_size = int(response.headers.get('Content-Length', 0))
        downloaded = 0
        
        with open(local_path, 'wb') as f:
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                
                # UI 업데이트 (메인 스레드에서)
                if hasattr(self, 'update_callback'):
                    self.update_callback(downloaded, total_size)
```

## 기술적 요구사항 (경량화)

### 1. **개발 플랫폼**
- **언어**: Python 3.8+ (최소 버전)
- **GUI**: tkinter (내장 모듈 활용)
- **배포**: PyInstaller --onefile --noconsole
- **목표 크기**: 15-20MB 이하

### 2. **최소 의존성**
```python
# 표준 라이브러리만 사용
import tkinter
import tkinter.ttk
import subprocess
import threading
import re
import time
import os
import webbrowser
import urllib.request
import json
import shutil
```

### 3. **메모리 최적화**
- 로그 순환 버퍼 (고정 크기)
- 불필요한 객체 즉시 해제
- 가비지 컬렉션 적극 활용

## 경량 UI 설계

### 1. **초간단 메인 윈도우** (450x350)
```
┌─ Cloudflared 터널 관리자 ─────────────────┐
│                                          │
│  Cloudflared: ✅ v2023.10.0 [재설치]    │
│  상태: ● 실행중     포트: [8501]         │
│                                          │
│  URL: https://abc123.trycloudflare.com   │
│  [복사] [열기]                           │
│                                          │
│  [시작] [중지]                           │
│                                          │
│  로그 (최근 10줄):                       │
│  ┌────────────────────────────────────┐  │
│  │tunnel started successfully         │  │
│  │URL detected: https://...           │  │
│  └────────────────────────────────────┘  │
│                                          │
│  [설정] [도움말] [종료]                  │
└──────────────────────────────────────────┘
```

### 2. **설치 상태별 UI 변화**

#### A. **Cloudflared 미설치 시**
```
┌─ Cloudflared 터널 관리자 ─────────────────┐
│                                          │
│  ⚠️  Cloudflared가 설치되지 않았습니다.   │
│                                          │
│  터널 기능을 사용하려면 먼저 설치해야     │
│  합니다.                                 │
│                                          │
│  [자동 설치] [수동 설치 안내]             │
│                                          │
│  💡 자동 설치 권장: 클릭 한 번으로       │
│     최신 버전을 자동으로 다운로드하고     │
│     설치합니다.                          │
│                                          │
│  [종료]                                  │
└──────────────────────────────────────────┘
```

#### B. **설치 진행 중**
```
┌─ Cloudflared 설치 중 ─────────────────────┐
│                                          │
│  📥 Cloudflared 다운로드 중...            │
│                                          │
│  ████████████░░░░░░░░ 65%                │
│  다운로드: 15.2MB / 23.4MB               │
│                                          │
│  예상 시간: 30초 남음                    │
│                                          │
│  [취소]                                  │
└──────────────────────────────────────────┘
```

### 3. **도움말 대화상자**
```
┌─ 사용법 도움말 ──────────────────────────┐
│                                          │
│  🔧 Cloudflared 터널 관리자 사용법        │
│                                          │
│  1. 시작 버튼을 클릭하여 터널을 시작     │
│  2. 생성된 URL을 복사하거나 브라우저에서 │
│     직접 열기                            │
│  3. 외부에서 해당 URL로 접속 가능        │
│  4. 작업 완료 후 중지 버튼으로 터널 종료 │
│                                          │
│  💡 팁:                                  │
│  • 포트는 로컬 서비스가 실행 중인 포트와│
│    동일해야 합니다                       │
│  • 터널은 임시적이며 프로그램 종료 시   │
│    자동으로 중지됩니다                   │
│                                          │
│  [확인]                                  │
└──────────────────────────────────────────┘
```

## 현재 소스코드 분석 결과

### 핵심 로직 구조

#### 1. **TunnelState 데이터 클래스**
```python
@dataclass
class TunnelState:
    port: int
    running: bool = False
    proc: Optional[subprocess.Popen] = None
    url: str = ""
    logs: List[str] = field(default_factory=list)
    auto_start: bool = True
```

#### 2. **터널 시작 로직**
```python
def start_cloudflared_tunnel(state: TunnelState, wait_for_url_seconds: int = 10):
    # 1. cloudflared 실행 파일 탐지
    # 2. 명령어 구성: [cloudflared, tunnel, --url, http://localhost:PORT, --no-autoupdate, --loglevel, info]
    # 3. subprocess.Popen으로 프로세스 시작
    # 4. 별도 스레드에서 stdout 모니터링
    # 5. URL 패턴 매칭으로 공개 URL 추출
```

#### 3. **URL 감지 패턴**
- `https://[hash].trycloudflare.com` (기본 패턴)
- `https://[hash].cfargotunnel.com` (대체 패턴)
- JSON 형태: `"url": "https://..."`
- 일반 URL 패턴 내 cloudflare 도메인

#### 4. **로그 처리**
- 실시간 stdout 읽기
- 로그 파일 저장 (`logs/cloudflared_tunnel.log`)
- 로그 레벨별 필터링
- 오류 처리 및 복구

### 주요 보안 고려사항

1. **입력 검증**: 포트 범위 (1-65535) 검증
2. **명령어 주입 방지**: shlex 사용한 안전한 명령어 구성
3. **프로세스 격리**: 별도 프로세스 및 스레드에서 실행
4. **리소스 정리**: 프로세스 종료 시 안전한 cleanup

## 추가 경량화 조치

### 1. **기능 제외 목록**
- QR 코드 생성 (PIL 의존성 제거)
- 로그 파일 저장 (디스크 I/O 제거)
- 시스템 트레이 (추가 라이브러리 제거)
- 고급 설정 옵션들
- 테마/스킨 기능

### 2. **패키징 최적화**
```bash
# 최경량 빌드 명령
pyinstaller --onefile --noconsole --optimize=2 \
    --exclude-module=PIL --exclude-module=numpy \
    --exclude-module=matplotlib --strip \
    tunnel_manager.py
```

### 3. **런타임 최적화**
- 불필요한 import 제거
- 지연 로딩 활용
- 메모리 풀 사용
- 객체 재사용

## 최소 시스템 요구사항

- **OS**: Windows 7 이상
- **RAM**: 128MB 여유 공간
- **디스크**: 100MB 여유 공간 (cloudflared 포함)
- **CPU**: 1GHz 이상
- **네트워크**: 인터넷 연결 (설치 및 터널 사용 시)

## 개발 우선순위 (경량화 중심)

1. **1단계**: Cloudflared 자동 감지 및 설치 시스템
2. **2단계**: 핵심 터널 시작/중지 로직
3. **3단계**: 최소 tkinter UI 구현 (설치 상태별)
4. **4단계**: URL 감지 및 복사 기능
5. **5단계**: 간단한 로그 표시 및 에러 처리
6. **6단계**: 경량 패키징 및 최적화

## 참고사항

### 현재 프로젝트의 관련 파일들
- `src/services/tunnel_service.py` - 터널 관리 핵심 로직
- `src/components/tunnel_ui.py` - Streamlit UI 컴포넌트
- `src/core/utils.py` - TunnelState 데이터 클래스
- `pages/91_tunnel_management.py` - 터널 관리 페이지

### 주요 기능 요소들
- Cloudflared 실행 파일 자동 탐지
- URL 패턴 매칭 (정규표현식 사용)
- 별도 스레드에서 프로세스 출력 모니터링
- 안전한 프로세스 종료 (terminate → kill)
- 로그 수집 및 표시

이 문서는 **Cloudflared 자동 설치 기능을 포함한 최소 자원으로 최대 효율**을 목표로 하는 경량 터널 관리 프로그램 개발을 위한 완전한 가이드입니다.