const solutions =
[
    {
        "question":"SYN플러딩",
        "answer":"TCP 프로토콜의 구조적 문제를 이용한 공격. SYN 패킷만 보내 자원이 고갈되도록 함"
    },
    {
        "question":"UDP플러딩",
        "answer":"대량의 UDP 패킷을 임의의 포트번호로 전송해 ICMP를 계속 생성시켜 고갈되도록 함"
    },
    {
        "question":"스머핑",
        "answer":"출발지 주소를 공격 대상의 IP로 설정해 네트워크 전체에 ICMP Echo패킷을 직접 브로드캐스팅해 마비시킴. 바운스 사이트를 이용해 공격"
    },
    {
        "question":"죽음의 핑",
        "answer":"ICMP 패킷(핑)을 아주 크게 만들어 전송해 단편화를 발생시킴. 재조합 버퍼의 오버플로우가 발생해 정상 서비스가 불가능 해짐"
    },
    {
        "question":"랜드어택",
        "answer":"출발지/목적지의 IP를 같은 패킷주소로 만들어 보내 자기자신에게 응답함"
    },
    {
        "question":"티어 드롭",
        "answer":"IP 패킷 재조합 과정에서 Fragment Offset 값을 중첩되도록 조작, 전송해 수신시스템에 문제가 발생하도록 만듦."
    },
    {
        "question":"봉크",
        "answer":"패킷을 보낼 때 순서번호를 모두 1번으로 조작"
    },
    {
        "question":"보잉크",
        "answer":"중간에 패킷 시퀀스 번호를 비정상적으로 보내 부하를 일으킴"
    },
    {
        "question":"HTTP GET 플러딩",
        "answer":"과도한 GET 메시지를 이용해 웹 서버 과부하를 유발"
    },
    {
        "question":"SlowLoris",
        "answer":"헤더 끝을 알리는 개행 문자열 대신 \\r\\n만 전송해 연결자원 소진"
    },
    {
        "question":"Rudy Attack",
        "answer":"요청 헤더의 Content-Length를 크게 설정해 바디를 매우 소량 보냄"
    },
    {
        "question":"Slow Read Attack",
        "answer":"TCP window 크기를 낮게 설정해 서버로 전달 후, 연결자원 고갈"
    },
    {
        "question":"Hulk Dos",
        "answer":"URL을 지속 변경(우회 목적)하면서 다량의 GET 요청 발생시킴"
    },
    {
        "question":"스니핑",
        "answer":"직접 공격 대신 데이터만 몰래 들여다보는 수동 공격"
    },
    {
        "question":"네트워크 스캐너/스니퍼",
        "answer":"네트워크 하드웨어, 소프트웨어의 취약점 파악을 위해 공격자가 취약점을 탐색하는 공격 도구"
    },
    {
        "question":"사전 패스워드 크래킹",
        "answer":"ID, PW 가능성이 있는 단어를 파일로 만들어 두고 대입"
    },
    {
        "question":"무차별 패스워드 크래킹",
        "answer":"무작위로 PW를 대입해 PW를 알아냄"
    },
    {
        "question":"패스워드 하이브리드 크래킹",
        "answer":"사전+무차별 결합"
    },
    {
        "question":"레인보우 테이블 패스워드 크래킹",
        "answer":"해당 해시 값을 테이블에서 검색해 역으로 PW를 알아냄"
    },
    {
        "question":"IP 스푸핑",
        "answer":"패킷 헤더를 위조 인증된 호스트의 IP 주소로 위조해 타깃에 전송"
    },
    {
        "question":"ARP 스푸핑",
        "answer":"MAC 주소를 위조해 특정 호스트로 나가는 패킷을 공격자가 스니핑 함"
    },
    {
        "question":"ICMP Redirect Attack",
        "answer":"메시지를 위조해 특정 패킷을 공격자가 스니핑 함"
    },
    {
        "question":"트로이목마",
        "answer":"겉보기에는 정상이지만 실행하면 악성코드 실행"
    },
    {
        "question":"스택가드",
        "answer":"Canary 라는 무결성 체크용 값을 복귀주소와 변수 사이에 대입"
    },
    {
        "question":"스택쉴드",
        "answer":"함수 시작 시 복귀주소를 Global RET 이라는 특수 스택에 저장 후 비교"
    },
    {
        "question":"ASLR",
        "answer":"메모리 공격 방어를 위해 주소 공간 배치를 난수화. 실행할 때마다 메모리 주소를 변경시켜 버퍼 오버플로우를 통한 특정주소 호출을 차단"
    },
    {
        "question":"XSS",
        "answer":"사용자가 미검증된 외부 입력 데이터를 포함한 웹페이지를 열람해, 웹페이지 내 부적절한 스크립트가 실행되는 공격"
    },
    {
        "question":"CSRF; Cross-Site Request Forgery",
        "answer":"사용자가 의지와 무관하게 공격자가 의도한 행위를 특정 웹사이트에 요청하게 하는 공격"
    },
    {
        "question":"SQL 삽입",
        "answer":"응용프로그램의 취약점을 이용해 악의적인 SQL 구문을 삽입 및 실행시켜 DB에 접근해 정보 탈취 및 조작"
    },
    {
        "question":"방화벽",
        "answer":"기업 내/외부 간 트래픽을 모니터링하여 시스템의 접근을 허용 또는 차단"
    },
    {
        "question":"웹 방화벽",
        "answer":"웹 애플리케이션 보안에 특화됨. SQL 삽입, XSS 같은 웹 공격을 탐지하고 차단"
    },
    {
        "question":"NAC; Network Access Control",
        "answer":"단말기가 내부 네트워크에 접속을 시도할 때 이를 제어하고 통제하는 기능을 제공하는 솔루션"
    },
    {
        "question":"IDS; Intrusion Detection System",
        "answer":"네트워크에 발생하는 이벤트를 모니터링하고, 침입을 실시간으로 탐지하는 시스템"
    },
    {
        "question":"IPS; Intrusion Prevention System",
        "answer":"네트워크에 대한 공격이나 침입을 실시간으로 자동 차단하는 시스템"
    },
    {
        "question":"WIPS",
        "answer":"무선 단말기의 접속을 자동으로 탐지하고 차단하는 시스템"
    },
    {
        "question":"UTM; Unified Threat Management",
        "answer":"다양한 보안 장비의 기능을 하나로 통합함. 보통 IPS+IDS+방화벽"
    },
    {
        "question":"VPN; Virtual Private Network",
        "answer":"인터넷 같은 공중망에 인증, 암호화, 터널링 기술을 활용해 마치 전용망을 사용하는 효과를 가지는 보안 솔루션"
    },
    {
        "question":"SIEM; Security Information & Event Management",
        "answer":"기업에서 생성 및 수집되는 다양한 데이터 분석을 통해 보안 위협 징후를 빠르게 판단하고 대응하는 보안 관제 솔루션"
    },
    {
        "question":"ESM; Enterprise Security Management",
        "answer":"보안 장비들을 통합 관리하는 기능 및 네트워크 보안 모니터링, 이벤트 위주의 단시간 위협 분석 및 DBMS 기반 보안 관리 솔루션"
    },
    {
        "question":"Anti-Spam Solution",
        "answer":"메일 서버 앞단에 위치해 프록시 메일 서버로 동작. 메일 바이러스 검사, 내부에서 외부로 본문 검색 기능을 통한 내부 정보 유출 방지"
    },
    {
        "question":"Secure OS",
        "answer":"운영체제 커널에 보안 기능을 추가한 솔루션"
    },
    {
        "question":"보안 USB",
        "answer":"보안 기능을 갖춘 USB 메모리. 사용자 식별/인증, 데이터 암/복호화, 임의복제 방지, 분실 시 데이터 삭제 기능"
    },
    {
        "question":"DLP; Data Loss Prevention; 데이터 유출 방지",
        "answer":"조직 내부의 중요 자료가 외부로 빠져나가는 것을 탐지하고 차단하는 솔루션.\r\n"
        +"정보 유출 방지를 위해 정보의 흐름에 대한 모니터링과 실시간 차단 기능 제공"
    },
    {
        "question":"DRM; Digital Right Management; 디지털 저작권 관리",
        "answer":"디지털 저작물에 대한 보호와 관리를 위한 솔루션. 파일 자체에 암호를 걸음.\r\n"
        +"문서 보안 솔루션으로도 사용할 수 있고 문서를 저장할 때 암호화하여 권한이 없는 사용자는 문서를 읽을 수 없음"
    },
    {
        "question":"부 채널 공격(Side Channel Attack)",
        "answer":"암호화 알고리즘의 물리적 특성을 측정하여 내부 비밀 정부를 부 채널에서 획득하는 공격기법"
    },
    {
        "question":"Drive By Download",
        "answer":"해커가 불특정 웹 서버와 웹 페이지에 악성 스크립트를 설치하고, 사용자 동의 없이 실행되어 의도된 멀웨어 서버로 연결시켜 감염"
    },
    {
        "question":"Watering Hole",
        "answer":"특정인이 자주 방문하는 웹사이트에 악성코드를 넣거나 URL로 자동 유인해 감염"
    },
    {
        "question":"비즈니스 스캠(SCAM)",
        "answer":"기업 이메일 계정을 도용해 무역 거래 대금을 가로채는 범죄"
    },
    {
        "question":"HeartBleed",
        "answer":"OpenSSL의 Heartbeat라는 확장모듈에서 클라이언트 요청 메시지를 처리할 때 데이터 길이 검증을 수행하지 않는 취약점을 이용해 시스템 메모리에 저장된 64KB 크기 데이터를 외부에서 아무 제한 없이 탈취"
    },
    {
        "question":"Crimeware",
        "answer":"중요한 금융정보, 인증정보를 탈취하거나 유출을 유도해 금전적인 이익 등 범죄행위를 목적으로 하는 악성코드"
    },
    {
        "question":"Tor Network",
        "answer":"네트워크 경로를 알 수 없도록 암호화 기법을 사용해 데이터를 전송하며, 익명으로 인터넷을 사용할 수 있는 가상 네트워크"
    },
    {
        "question":"MITM 공격",
        "answer":"네트워크 통신을 조작해 통신 내용을 도청 및 조작. 통신을 연결하는 사이 중간에 침입해 두 사람의 정보를 탈취하는 중간자 공격"
    },
    {
        "question":"DNS스푸핑",
        "answer":"DNS 응답(IP주소)를 조작하거나 DNS 서버의 캐시 정보를 조작해 의도하지 않은 주소로 접속하게 만듦. = DNS Cache Poisoning"
    },
    {
        "question":"Port Scanning",
        "answer":"공격자가 침입 전 대상 호스트에 어떤 포트가 활성화되어 있는지 확인. 침입 전 취약점을 분석하기 위한 사전 작업"
    },
    {
        "question":"Directory Listing 취약점",
        "answer":"서버의 미흡한 설정으로 인덱싱 기능이 활성화된 경우, 공격자가 강제 브라우징을 통해서 서버 내 모든 디렉토리 및 파일 목록을 볼 수 있는 취약점"
    },
    {
        "question":"Reverse Shell",
        "answer":"타깃 서버가 클라이언트(공격자)로 접속해서 클라이언트가 타깃 서버의 쉘을 획득해서 공격"
    },
    {
        "question":"Exploit",
        "answer":"SW나 HW의 버그, 취약점을 이용해 공격자가 의도한 동작이나 명령을 실행하도록 하는 코드, 행위"
    },
    {
        "question":"Stuxnet(스턱스넷 공격)",
        "answer":"독일 지맨스사의 SCADA 시스템을 공격목표로 제작된 악성 코드. 원자력, 전기, 철강, 반도체, 화학 등 주요 산업 기반 시설의 제어시스템에 침투해 오작동을 일으킴"
    },
    {
        "question":"Credential Stuffing",
        "answer":"사용자 계정을 탈취해서 공격. 다른 곳에서 유출된 로그인 정보를 다른 웹사이트에 무작위로 대입해 로그인 되면 정보를 유출시킴"
    },
    {
        "question":"Honeypot",
        "answer":"비정상 접근을 탐지하기 위해 의도적으로 설치하는 유인 시스템"
    },
    {
        "question":"OWASP Top 10",
        "answer":"웹 애플리케이션 취약점 중 공격 빈도가 높고, 보안상 큰 영향을 줄 수 있는 10가지 취약점에 대한 대응 방안을 제공하는 웹 보안기술 가이드"
    },
    {
        "question":"Finger Printing",
        "answer":"멀티미디어 콘텐츠에 저작권 정보와 구매한 사용자 정보를 삽입해 불법 배포자에 대한 위치 추적이 가능한 기술"
    },
    {
        "question":"Water Marking",
        "answer":"디지털 콘텐츠에 저작권자 정보를 삽입해 불법 복제시 워터마크를 추출, 원소유자를 증명할 수 있는 콘텐츠 보호 기술"
    },
    {
        "question":"FDS; Fraud Delection System; 이상금융거래탐지시스템",
        "answer":"전자금융거래에 사용되는 단말기 정보, 접속 정보, 거래 정보 등을 종합 분석해 의심 거래를 탐지하고, 이상 거래를 차단하는 시스템"
    },
    {
        "question":"CC; Common Criteria",
        "answer":"정보기술의 보안 기능과 보증에 대한 평가 기준(등급), 정보보호 시스템의 보안 기능 및 보증 요구사항 평가를 위해 공통으로 제공되는 국제 평가 기준"
    },
    {
        "question":"C-TAS; Cyber Threats Analysis System; 사이버 위협정보 분석 공유시스템",
        "answer":"사이버 위협정보를 체계적으로 수립해서 인터넷진흥원(KISA) 주관으로 관계 기관과 자동화된 정보 공유를 할 수 있는 침해 예방 대응 시스템"
    },
    {
        "question":"PAM; Pluggable Authentication Module; 정착형 인증 모듈",
        "answer":"리눅스 내에서 사용되는 각종 애플리케이션 인증을 위해 제공되는 다양한 인증용 라이브러리"
    },
    {
        "question":"CVE; Common Vulnerabilities and Exposures",
        "answer":"미국 비영리 회사인 MITRE사에서 공개적으로 알려진 SW의 보안 취약점을 표준화한 식별자 목록.\r\n"
        +"규칙: 정답 - (연도) - (순서)"
    },
    {
        "question":"CWE; Common Weakness Enumeration",
        "answer":"미국 비영리 회사인 MITRE사가 SW에서 공통 발생하는 약점을 체계적으로 분류한 목록. 소스코드 취약점을 정의한 DB.\r\n"
        +"SW 약점은 SDLC 과정에서 발생할 수 있기 때문에 설계, 아키텍처, 코드 단계 등에 대한 취약점 목록을 포함"
    },
    {
        "question":"ISMS; Information Security Management System",
        "answer":"조직의 주요 정보자산을 보호하기 위해 정보보호 관리 절차와 과정을 체계적으로 수립하여 지속적으로 관리하고 운영하기 위한 종합 체계"
    },
    {
        "question":"PIMS; Personal Information Management System",
        "answer":"기업이 개인정보보호 활동을 체계적,지속적으로 수행하기 위해 필요한 보호조치 체계를 구축했는지 여부를 점검, 평가하여 기업에게 부여하는 인증제도"
    },
    {
        "question":"PIA; Privacy Impact Assessment",
        "answer":"개인정보를 활용하는 새로운 정보 시스템 도입 또는 기존 정보 시스템의 변경 시, 프라이버시에 미치는 영향에 대해 사전 조사 및 예측 검토해 개선방안을 도출하는 절차"
    },
    {
        "question":"TKIP; Temporal Key Integrity Protocol",
        "answer":"임시 키 무결성 프로토콜. IEEE 802.11i의 암호화 방식으로 초기 Wi-Fi 장비에서 널리 사용된 안전하지 않은 WEP 암호화 표준을 대체함"
    },
    {
        "question":"Format String Attack",
        "answer":"외부로부터 입력된 값을 검증하지 않고 입출력 함수의 서식 문자열을 사용하는 경우 발생하는 취약점 공격.\r\n"
        +"printf(argv[1]) 등 서식 문자열을 인자로 하는 함수 사용 시 사용자 입력값을 통해 지정된다면 공격자가 이를 조작해 메모리 내용을 참조하거나 특정 영역 값을 변경 가능"
    },
    {
        "question":"Race Condition Attack",
        "answer":"둘 이상의 프로세스나 스레드가 공유자원을 동시에 접근할 때 순서에 따라 원치 않는 결과가 발생하는 조건/상황.\r\n"
        +"실행되는 프로세스가 임시파일을 만드는 경우, 악의적인 프로그램을 통해 프로세스 중에 끼어들어 임시파일을 심볼릭 링크하여 악의적인 행위를 수행함"
    },
    {
        "question":"Key Logger Attack",
        "answer":"키보드 움직임을 탐지해 저장하여 중요한 개인 정보를 몰래 빼가는 해킹 공격"
    },
    {
        "question":"Rootkit",
        "answer":"시스템 침입 사실을 숨긴 채 차후 침입을 위한 백도어, 트로이목마 설치, 원격 접근, 권한 획득 등 주로 불법적인 해킹에 사용되는 기능을 제공하는 프로그램 모음"
    },
    {
        "question":"Spear Phishing(스피어피싱)",
        "answer":"사회공학의 한 기법. 이메일로 위장한 메일을 지속 발송하여, 발송 메일의 본문 링크나 첨부된 파일을 클릭하도록 유도해 개인정보를 탈취"
    },
    {
        "question":"Smishing(스미싱)",
        "answer":"SMS+Phising 문자메시지를 이용해 신뢰할 수 있는 사람이 보낸 것처럼 가장하여 개인 비밀번호 요구 또는 휴대폰 소액 결제를 유도하는 공격"
    },
    {
        "question":"Qshing(큐싱)",
        "answer":"QR코드+Phising 큐알코드를 통해 악성 앱을 내려받도록 유도. 최근 제로페이 확산에 따라 피해 증가"
    },
    {
        "question":"Botnet",
        "answer":"악성 프로그램에 감염되어 악의적인 의도로 사용될 수 있는 다수의 컴퓨터들이 네트워크로 연결된 형태"
    },
    {
        "question":"APT 공격",
        "answer":"특수목적의 조직이 하나의 표적에 대해 다양한 IT 기술을 이용해, 지속적으로 정보를 수집하고 취약점을 분석해 피해를 주는 공격"
    },
    {
        "question":"Supply Chain Attack (공급망 공격)",
        "answer":"SW 개발사 네트워크에 침투해 악의적인 코드 삽입 또는 악의적인 파일 변경을 통해, 사용자 PC에 SW를 설치 또는 업데이트 시 자동 감염되게 함"
    },
    {
        "question":"Zero Day Attack",
        "answer":"보안 취약점이 발견되어 널리 공표되기 전에 이뤄지는 보안 공격. 공격의 신속성을 의미하며 대응책 공표 전이므로 대응 방법이 없음"
    },
    {
        "question":"Worm",
        "answer":"스스로를 복제해 네트워크 연결로 전파되는 악성 SW 프로그램. 바이러스는 기생하지만 이것은 독자적으로 실행되므로 다른 실행 프로그램이 필요 없음"
    },
    {
        "question":"Malicious Bot (악성 봇)",
        "answer":"스스로 실행 불가능. 해커가 원격에서 제어/실행 가능함. 취약점이나 백도어 등으로 전파되며 스팸 메일 전송이나 DDoS에 악용. 좀비 PC가 해당됨"
    },
    {
        "question":"Cyber Kill Chain",
        "answer":"록히드 마틴의 공격형 방위시스템. 지능적이고 지속적으로 사이버 공격에 대해 7단계 프로세스별 공격분석 및 대응을 체계화한 APT 공격 방어 분석 모델"
    },
    {
        "question":"Ransomware",
        "answer":"감염된 시스템의 파일들을 암호화하여 복호화할 수 없게 하고, 암호화된 파일을 인질로 잡고 몸값을 요구함. 현금이나 비트코인 등을 받고 복호화해주는 범죄행위에 이용"
    },
    {
        "question":"Evil Twin (이블 트윈 공격)",
        "answer":"무선 WiFi 피싱 기법. 공격자가 합법적인 WiFi 제공자인척 하며 핫스팟에 연결한 무선 사용자들의 정보를 탈취"
    },
    {
        "question":"Social Engineering (사회공학)",
        "answer":"사람들의 심리, 행동 양식을 교묘하게 이용해 정보를 얻는 공격. 사례로 상대방의 자만심이나 권한을 이용하는 공격 및 도청이 있음"
    },
    {
        "question":"Trustzone",
        "answer":"프로세서 안에 독립적인 보안 구역을 따로 두어 중요한 정보를 보호하는 HW 기반의 보안 기술. ARM사에서 개발"
    },
    {
        "question":"Typosquattiong (타이포스쿼팅)",
        "answer":"사용자가 주소에 오타내는 걸 이용해 유사한 유명 도메인을 미리 등록함. = URL 하이재킹"
    }
];