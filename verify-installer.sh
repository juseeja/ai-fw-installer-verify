#!/bin/bash
set -euo pipefail
export LC_ALL=C
umask 077
unset TAR_OPTIONS

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

TRUSTED_KEYS=(
    # 주 키 keyId 4dbb255ff3c36cda (2026-10-11)
    '-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9cfqA52nvVlCKZi1Tyy3i9yenbEwtAsSEzOeLwerRBk=
-----END PUBLIC KEY-----'
    # 예비 키 keyId 9a1a66bdaee15e01 — 주 키를 잃거나 폐기할 때만 쓴다(오프라인 보관)
    '-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxHYGy9z4yQBzlAkqna5NvbdAh8GVAEzbWMRBYm7tYiA=
-----END PUBLIC KEY-----'
)
work_dir=''
dest=''
dest_created=0
failure_reason='검증 명령 실행 실패'
restore_directories() {
    local parent
    [[ -d "$dest" && ! -L "$dest" ]] || return 1
    chmod 700 -- "$dest" || return 1
    while IFS= read -r parent; do
        if [[ -d "$dest/$parent" && ! -L "$dest/$parent" ]]; then
            chmod 700 -- "$dest/$parent" || return 1
        fi
    done < "$work_dir/dirs.sorted"
}
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ $rc -ne 0 && $dest_created -eq 1 ]]; then
        restore_directories 2>/dev/null || :
        if ! rm -rf -- "$dest" 2>/dev/null; then failure_reason="$failure_reason · 대상 디렉터리 정리 실패"; fi
    fi
    if [[ -n "$work_dir" ]]; then rm -rf -- "$work_dir"; fi
    if [[ $rc -ne 0 ]]; then log_error "$failure_reason"; fi
    exit "$rc"
}
fail() { failure_reason=$1; exit 1; }
trap cleanup EXIT
trap 'fail "검증 중단"' HUP INT TERM

[[ $# -ge 3 ]] || fail '사용법: verify-installer.sh <tar.gz> <manifest> <manifest.sig> [--pubkey <PEM>] [--dest <디렉터리>]'
archive_input=$1
manifest_input=$2
signature_input=$3
shift 3
pubkey=''
pubkey_seen=0
dest_seen=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pubkey)
            [[ $# -ge 2 && $pubkey_seen -eq 0 && -n "$2" ]] || fail '--pubkey 인수가 잘못되었거나 중복입니다'
            pubkey=$2; pubkey_seen=1; shift 2 ;;
        --dest)
            [[ $# -ge 2 && $dest_seen -eq 0 && -n "$2" ]] || fail '--dest 인수가 잘못되었거나 중복입니다'
            dest=$2; dest_seen=1; shift 2 ;;
        *) fail '알 수 없는 옵션입니다' ;;
    esac
done
OPENSSL=${OPENSSL:-openssl}
tar_version=$(tar --version 2>/dev/null) || fail 'GNU tar가 필요합니다'
[[ "$tar_version" == *'GNU tar'* ]] || fail 'GNU tar가 필요합니다'
for input_file in "$archive_input" "$manifest_input" "$signature_input"; do
    [[ -f "$input_file" ]] || fail '입력 파일을 읽을 수 없습니다'
done
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/aifw-verify.XXXXXX")
cp -- "$archive_input" "$work_dir/archive.tar.gz"
cp -- "$manifest_input" "$work_dir/manifest"
cp -- "$signature_input" "$work_dir/manifest.sig"
archive="$work_dir/archive.tar.gz"
manifest="$work_dir/manifest"

sha256_file() {
    local result
    result=$(sha256sum "$1" 2>/dev/null) || return 1
    printf '%s\n' "${result%% *}"
}
file_size() { wc -c < "$1" | tr -d '[:space:]'; }
decimal_size() {
    local value=$1
    while [[ ${#value} -gt 1 && "$value" == 0* ]]; do value=${value#0}; done
    printf '%s\n' "$value"
}
safe_path() {
    [[ "$1" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
    case "/$1/" in *//*|*/../*|*/./*) return 1 ;; esac
}
public_key_id() {
    "$OPENSSL" pkey -pubin -in "$1" -pubout -outform DER > "$work_dir/public.der" 2>/dev/null || return 1
    local header size digest
    header=$(od -An -tx1 -N12 "$work_dir/public.der" | tr -d '[:space:]') || return 1
    size=$(file_size "$work_dir/public.der") || return 1
    [[ "$size" == 44 && "$header" == 302a300506032b6570032100 ]] || return 1
    tail -c 32 "$work_dir/public.der" > "$work_dir/public.raw" || return 1
    digest=$(sha256_file "$work_dir/public.raw") || return 1
    printf '%s\n' "${digest:0:16}"
}

IFS= read -r sig_line < "$work_dir/manifest.sig" || fail '서명 형식 오류: 한 줄이어야 합니다'
[[ "$(file_size "$work_dir/manifest.sig")" == "$((${#sig_line} + 1))" ]] || fail '서명 형식 오류: 한 줄이어야 합니다'
[[ "$sig_line" =~ ^([0-9a-f]{16})\ ([A-Za-z0-9+/]+={0,2})$ ]] || fail '서명 형식 오류: keyId 또는 base64'
signature_key_id=${BASH_REMATCH[1]}
signature_base64=${BASH_REMATCH[2]}
printf '%s' "$signature_base64" | "$OPENSSL" base64 -d -A > "$work_dir/signature.bin" 2>/dev/null || fail '서명 형식 오류: base64 해독 실패'
[[ "$(file_size "$work_dir/signature.bin")" == 64 ]] || fail '서명 형식 오류: ed25519 서명 길이'
canonical_base64=$("$OPENSSL" base64 -A -in "$work_dir/signature.bin")
[[ "$canonical_base64" == "$signature_base64" ]] || fail '서명 형식 오류: 정규 base64가 아닙니다'

key_count=0
if [[ $pubkey_seen -eq 1 ]]; then
    log_warning '시험 키로 검증 — 운영 반입이 아님'
    [[ -f "$pubkey" ]] || fail '시험 공개키를 읽을 수 없습니다'
    cp -- "$pubkey" "$work_dir/key.0.pem"
    key_count=1
else
    for trusted_key in ${TRUSTED_KEYS[@]+"${TRUSTED_KEYS[@]}"}; do
        printf '%s\n' "$trusted_key" > "$work_dir/key.$key_count.pem"
        key_count=$((key_count + 1))
    done
fi
[[ $key_count -gt 0 ]] || fail '신뢰 공개키가 없습니다'
matched_key=''
for ((key_index=0; key_index<key_count; key_index++)); do
    key_id=$(public_key_id "$work_dir/key.$key_index.pem") || fail '신뢰 공개키가 ed25519 PEM 형식이 아닙니다'
    if [[ "$key_id" == "$signature_key_id" ]]; then matched_key="$work_dir/key.$key_index.pem"; break; fi
done
[[ -n "$matched_key" ]] || fail 'keyId 불일치: 신뢰 공개키에 없는 서명자입니다'
"$OPENSSL" pkeyutl -verify -pubin -inkey "$matched_key" -rawin -in "$manifest" -sigfile "$work_dir/signature.bin" > /dev/null 2>&1 || fail '서명 검증 실패'
log_info 'manifest 서명 확인 완료'

tr -d '\000' < "$manifest" > "$work_dir/manifest.no-nul"
cmp -s "$manifest" "$work_dir/manifest.no-nul" || fail 'manifest 형식 오류: NUL 문자'
product_seen=0
version_seen=0
source_seen=0
archive_seen=0
member_count=0
line_number=0
member_paths=()
member_modes=()
member_sizes=()
member_hashes=()
: > "$work_dir/member.paths"
: > "$work_dir/allowed.dirs"
while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    if [[ $line_number -eq 1 ]]; then
        [[ "$line" == 'ai-fw-installer-manifest 1' ]] || fail 'manifest 헤더 오류'
        continue
    fi
    case "$line" in
        'product ai-fw-installer')
            [[ $product_seen -eq 0 ]] || fail 'manifest 필수 줄 중복: product'
            product_seen=1 ;;
        version\ *)
            [[ $version_seen -eq 0 ]] || fail 'manifest 필수 줄 중복: version'
            [[ "$line" =~ ^version\ ([A-Za-z0-9][A-Za-z0-9._-]*)$ ]] || fail 'manifest version 형식 오류'
            version=${BASH_REMATCH[1]}; version_seen=1 ;;
        source\ *)
            [[ $source_seen -eq 0 ]] || fail 'manifest 필수 줄 중복: source'
            [[ "$line" =~ ^source\ ([0-9a-f]{40}|[0-9a-f]{64})$ ]] || fail 'manifest source 형식 오류'
            source_commit=${BASH_REMATCH[1]}; source_seen=1 ;;
        archive\ *)
            [[ $archive_seen -eq 0 ]] || fail 'manifest 필수 줄 중복: archive'
            [[ "$line" =~ ^archive\ ([A-Za-z0-9._-]+)\ ([0-9a-f]{64})\ ([0-9]+)$ ]] || fail 'manifest archive 형식 오류'
            archive_name=${BASH_REMATCH[1]}; archive_hash=${BASH_REMATCH[2]}; archive_size=$(decimal_size "${BASH_REMATCH[3]}")
            archive_seen=1 ;;
        member\ *)
            [[ "$line" =~ ^member\ (0?[0-7]{3})\ ([0-9]+)\ ([0-9a-f]{64})\ ([A-Za-z0-9._/-]+)$ ]] || fail 'manifest member 형식 오류'
            member_modes[member_count]=${BASH_REMATCH[1]}
            member_sizes[member_count]=$(decimal_size "${BASH_REMATCH[2]}")
            member_hashes[member_count]=${BASH_REMATCH[3]}
            member_path=${BASH_REMATCH[4]}
            safe_path "$member_path" || fail 'manifest 경로가 안전하지 않습니다'
            member_paths[member_count]=$member_path
            member_count=$((member_count + 1))
            printf '%s\n' "$member_path" >> "$work_dir/member.paths"
            parent=$member_path
            while [[ "$parent" == */* ]]; do
                parent=${parent%/*}
                printf '%s\n' "$parent" >> "$work_dir/allowed.dirs"
            done ;;
        *) fail 'manifest 알 수 없는 줄 또는 형식 오류' ;;
    esac
done < "$manifest"
[[ $line_number -gt 0 && $product_seen -eq 1 && $version_seen -eq 1 && $source_seen -eq 1 && $archive_seen -eq 1 && $member_count -gt 0 ]] || fail 'manifest 필수 줄 누락'
[[ "$archive_name" == "ai-fw-installer-$version.tar.gz" ]] || fail 'manifest archive 파일명과 version 불일치'
sort "$work_dir/member.paths" > "$work_dir/member.sorted"
uniq -d "$work_dir/member.sorted" > "$work_dir/duplicates"
[[ ! -s "$work_dir/duplicates" ]] || fail 'manifest member 경로 중복'
sort -u "$work_dir/allowed.dirs" > "$work_dir/dirs.sorted"
comm -12 "$work_dir/member.sorted" "$work_dir/dirs.sorted" > "$work_dir/conflicts"
[[ ! -s "$work_dir/conflicts" ]] || fail 'manifest 파일과 상위 디렉터리 경로 충돌'
[[ "$(sha256_file "$archive")" == "$archive_hash" ]] || fail 'tar sha256 불일치'
[[ "$(file_size "$archive")" == "$archive_size" ]] || fail 'tar 크기 불일치'

tar --absolute-names --quoting-style=escape -tvzf "$archive" > "$work_dir/tar.verbose" 2> "$work_dir/tar.error" || fail 'tar 목록을 읽을 수 없습니다'
tar --absolute-names --quoting-style=escape -tzf "$archive" > "$work_dir/tar.paths" 2> "$work_dir/tar.error" || fail 'tar 경로 목록을 읽을 수 없습니다'
: > "$work_dir/tar.files"
: > "$work_dir/tar.dirs"
: > "$work_dir/tar.entries"
exec 3< "$work_dir/tar.paths" 4< "$work_dir/tar.verbose"
while IFS= read -r member_path <&3; do
    IFS= read -r details <&4 || fail 'tar 목록 항목 수 불일치'
    member_type=${details:0:1}
    [[ "$details" != *' link to '* ]] || fail 'tar 금지 타입: 하드링크'
    case "$member_type" in -|d) ;; *) fail "tar 금지 타입: $member_type" ;; esac
    while [[ "$member_path" == ./* ]]; do member_path=${member_path#./}; done
    if [[ "$member_type" == d ]]; then member_path=${member_path%/}; fi
    safe_path "$member_path" || fail 'tar 경로가 안전하지 않습니다'
    printf '%s\n' "$member_path" >> "$work_dir/tar.entries"
    if [[ "$member_type" == - ]]; then
        printf '%s\n' "$member_path" >> "$work_dir/tar.files"
    else
        printf '%s\n' "$member_path" >> "$work_dir/tar.dirs"
    fi
done
if IFS= read -r details <&4; then fail 'tar 목록 항목 수 불일치'; fi
exec 3<&- 4<&-
sort "$work_dir/tar.entries" > "$work_dir/entries.sorted"
uniq -d "$work_dir/entries.sorted" > "$work_dir/duplicates"
[[ ! -s "$work_dir/duplicates" ]] || fail 'tar 경로 중복'
sort "$work_dir/tar.files" > "$work_dir/files.sorted"
sort "$work_dir/tar.dirs" > "$work_dir/tardirs.sorted"
comm -23 "$work_dir/tardirs.sorted" "$work_dir/dirs.sorted" > "$work_dir/extra"
[[ ! -s "$work_dir/extra" ]] || fail 'tar 허용되지 않은 디렉터리'
comm -23 "$work_dir/files.sorted" "$work_dir/member.sorted" > "$work_dir/extra"
[[ ! -s "$work_dir/extra" ]] || fail 'tar manifest에 없는 파일 추가'
comm -13 "$work_dir/files.sorted" "$work_dir/member.sorted" > "$work_dir/missing"
[[ ! -s "$work_dir/missing" ]] || fail 'tar manifest 파일 누락'

if [[ $dest_seen -eq 0 ]]; then dest="$PWD/ai-fw-installer-$version"; fi
case "$dest" in /*) ;; *) dest="$PWD/$dest" ;; esac
while [[ "$dest" != / && "$dest" == */ ]]; do dest=${dest%/}; done
[[ ! -e "$dest" && ! -L "$dest" ]] || fail '대상 디렉터리가 이미 있습니다'
mkdir -- "$dest" 2>/dev/null || fail '새 대상 디렉터리를 만들 수 없습니다'
dest_created=1
tar --no-same-owner --no-same-permissions -xzf "$archive" -C "$dest" 2> "$work_dir/tar.error" || fail 'tar 압축 해제 실패'
restore_directories || fail '해제 후 디렉터리 권한 설정 실패'
for ((member_index=0; member_index<member_count; member_index++)); do
    member_path=${member_paths[$member_index]}
    member_file="$dest/$member_path"
    [[ -f "$member_file" && ! -L "$member_file" ]] || fail '해제 후 일반 파일이 아닙니다'
    [[ "$(sha256_file "$member_file")" == "${member_hashes[$member_index]}" ]] || fail "해제 후 파일 sha256 불일치: $member_path"
    [[ "$(file_size "$member_file")" == "${member_sizes[$member_index]}" ]] || fail "해제 후 파일 크기 불일치: $member_path"
    chmod "${member_modes[$member_index]}" -- "$member_file" || fail '해제 후 파일 모드 적용 실패'
done
find "$dest" -mindepth 1 -print0 > "$work_dir/extracted.paths" || fail '해제 후 경로 검사 실패'
: > "$work_dir/extracted.files"
: > "$work_dir/extracted.dirs"
while IFS= read -r -d '' member_file; do
    member_path=${member_file#"$dest/"}
    safe_path "$member_path" || fail '해제 후 안전하지 않은 경로'
    [[ ! -L "$member_file" ]] || fail '해제 후 추가 링크 발견'
    if [[ -f "$member_file" ]]; then
        printf '%s\n' "$member_path" >> "$work_dir/extracted.files"
    elif [[ -d "$member_file" ]]; then
        printf '%s\n' "$member_path" >> "$work_dir/extracted.dirs"
    else
        fail '해제 후 금지 타입 발견'
    fi
done < "$work_dir/extracted.paths"
sort "$work_dir/extracted.files" > "$work_dir/extracted.sorted"
cmp -s "$work_dir/extracted.sorted" "$work_dir/member.sorted" || fail '해제 후 파일 집합 불일치'
sort "$work_dir/extracted.dirs" > "$work_dir/extracted.dirs.sorted"
comm -23 "$work_dir/extracted.dirs.sorted" "$work_dir/dirs.sorted" > "$work_dir/extra"
[[ ! -s "$work_dir/extra" ]] || fail '해제 후 추가 디렉터리 발견'
log_success "검증 완료 · version $version · source $source_commit · 경로 $dest"
