# ai-fw-installer-verify

AI-Firewall 설치기(서명 tar)를 풀기 전에 확인하는 검증기입니다. 받은 설치기가 배포한 그대로인지 서명과 파일 해시로 확인하고, 통과한 것만 새 디렉터리에 풉니다.

## 사용

```bash
wget -O verify-installer.sh https://raw.githubusercontent.com/juseeja/ai-fw-installer-verify/main/verify-installer.sh
bash ./verify-installer.sh ./ai-fw-installer-<버전>.tar.gz ./manifest ./manifest.sig --dest ./ai-fw-installer-<버전>
```

tar·manifest·manifest.sig 세 파일은 현장 엔지니어에게서 받습니다. 검증이 실패하면 아무것도 남기지 않고 이유를 한 줄로 알려 줍니다. 그때는 설치하지 마세요.

필요한 도구: bash · OpenSSL 3 · sha256sum · GNU tar (Ubuntu 24.04 기본 설치에 모두 있음)

## 신뢰하는 서명 키

| 용도 | keyId |
|---|---|
| 주 키 | `4dbb255ff3c36cda` |
| 예비 키 | `9a1a66bdaee15e01` |

공개키는 `verify-installer.sh` 의 `TRUSTED_KEYS` 에 들어 있습니다. keyId = sha256(ed25519 공개키 32바이트) 앞 16글자.
