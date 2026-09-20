#!/usr/bin/env bash
set -uo pipefail

MAX_SIZE=2097152

SCAN_PATHS=(
    "/etc"
    "/home"
    "/opt"
    "/var/www"
    "/srv"
    "/root"
)

EXTENSIONS=(
    "conf" "config" "cfg" "ini" "env" "properties"
    "yaml" "yml" "json" "xml" "toml"
    "php" "py" "rb" "pl" "sh" "bash" "zsh" "ps1"
    "tf" "tfvars" "service" "sql" "txt"
)

FILENAMES=(
    ".env" ".netrc" ".pgpass" ".my.cnf" ".npmrc" ".pypirc"
    ".git-credentials"
    ".bash_history" ".zsh_history" ".python_history"
    ".mysql_history" ".psql_history"
    "wp-config.php" "application.properties"
    "docker-compose.yml" "docker-compose.yaml"
)

EXCLUDE_PATHS=(
    "/proc" "/proc/*"
    "/sys" "/sys/*"
    "/dev" "/dev/*"
    "/run" "/run/*"
    "/usr/share/doc" "/usr/share/doc/*"
    "/usr/share/man" "/usr/share/man/*"
    "/usr/share/locale" "/usr/share/locale/*"
    "/var/cache" "/var/cache/*"
    "*/node_modules/*"
    "*/vendor/*"
    "*/.cache/*"
    "*/__pycache__/*"
    "*/.git/objects/*"
    "*/.git/pack/*"
)

LOG_PATHS=("/var/log")

LOG_PATTERNS=(
    "*.log" "*.log.[0-9]*" "*.log.[0-9]*.gz" "*.gz"
    "auth.log*" "syslog*" "messages*" "secure*" "daemon.log*" "kern.log*"
)

PLACEHOLDERS=(
    "password" "passwd" "secret" "changeme" "change_me" "change-me"
    "example" "examplepassword" "test" "testing" "dummy"
    "foobar" "foo" "bar" "null" "none" "undefined"
    "xxxxxxxx" "xxxxx" "yourpassword" "your_password"
    "your-secret" "your_secret"
)

PRIVATE_KEY_RE='-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----'
CONNECTION_RE='(mysql|postgres(ql)?|mongodb(\+srv)?|redis|mssql|amqp|ldap(s)?|ftp|ssh)://[^[:space:]/:@]+:[^[:space:]@]+@'
AWS_ACCESS_KEY_RE='AKIA[0-9A-Z]{16}'
GITHUB_TOKEN_RE='(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}'
AUTH_HEADER_RE='Authorization:[[:space:]]*(Basic|Bearer)[[:space:]]+[A-Za-z0-9._~+/-]{8,}'
JWT_RE='eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}'
STRICT_CREDENTIAL_RE='([A-Za-z0-9_.-]*(password|passwd|passphrase|client[_-]?secret|api[_-]?key|secret[_-]?key|access[_-]?token|refresh[_-]?token)[A-Za-z0-9_.-]*)[[:space:]]*[:=][[:space:]]*["'\'']?[^[:space:]"'\'']{6,}'
GENERIC_CREDENTIAL_RE='([A-Za-z0-9_.-]*(password|passwd|pwd|passphrase|secret|token|credential|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token)[A-Za-z0-9_.-]*)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}'

MODE="${1:-}"
[[ -n "$MODE" ]] && shift

ROOTS=()
SHOW_LOW=false
REALLY_ALL=false

declare -A SEEN_FINDINGS=()

while (($#)); do
    case "$1" in
        --show-low) SHOW_LOW=true ;;
        --really-all) REALLY_ALL=true ;;
        -h|--help) MODE="help" ;;
        *) ROOTS+=("$1") ;;
    esac
    shift
done

usage() {
cat <<'EOF'
Credential Hunt

Usage:
  credhunt.sh filtered [--show-low]
  credhunt.sh all [PATH...] [--show-low]
  credhunt.sh all / --really-all [--show-low]
  credhunt.sh logs [PATH...] [--show-low]

Modes:
  filtered   Search configured high-value directories and file types.
  all        Search readable regular files, excluding known noisy/virtual paths.
  logs       Search configured log directories, including gzip-compressed logs.

Options:
  --show-low    Include low-confidence generic credential matches.
  --really-all  Disable path exclusions in ALL mode.

Examples:
  ./credhunt.sh filtered
  ./credhunt.sh filtered --show-low
  ./credhunt.sh all /
  ./credhunt.sh all /home /etc /opt
  ./credhunt.sh all / --show-low
  ./credhunt.sh all / --really-all --show-low
  ./credhunt.sh logs
  ./credhunt.sh logs /var/log /opt/app/logs
EOF
}

case "$MODE" in
    all|filtered|logs) ;;
    help|-h|--help|"") usage; exit 0 ;;
    *) echo "Unknown mode: $MODE" >&2; usage >&2; exit 1 ;;
esac

is_excluded() {
    local file="$1" pattern
    $REALLY_ALL && return 1
    for pattern in "${EXCLUDE_PATHS[@]}"; do
        [[ "$file" == $pattern ]] && return 0
    done
    return 1
}

is_placeholder_line() {
    local line="$1" lower placeholder
    lower=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')

    [[ "$lower" =~ \$\{[^}]+\} ]] && return 0
    [[ "$lower" =~ \$[a-z_][a-z0-9_]* ]] && return 0
    [[ "$lower" == *"{{"*"}}}"* ]] && return 0
    [[ "$lower" == *"<password>"* ]] && return 0
    [[ "$lower" == *"<secret>"* ]] && return 0

    for placeholder in "${PLACEHOLDERS[@]}"; do
        [[ "$lower" =~ [:=\"\'\ ]${placeholder}[\"\',\;\ ]*$ ]] && return 0
    done
    return 1
}

extract_finding_value() {
    local rule="$1" line="$2" content value
    content="${line#*:}"

    case "$rule" in
        "AWS access key")
            value=$(printf '%s\n' "$content" | LC_ALL=C grep -aoE -- "$AWS_ACCESS_KEY_RE" | head -n 1)
            ;;
        "GitHub token")
            value=$(printf '%s\n' "$content" | LC_ALL=C grep -aoE -- "$GITHUB_TOKEN_RE" | head -n 1)
            ;;
        "JWT")
            value=$(printf '%s\n' "$content" | LC_ALL=C grep -aoE -- "$JWT_RE" | head -n 1)
            ;;
        "Authorization header")
            value=$(printf '%s\n' "$content" | LC_ALL=C grep -aioE -- "$AUTH_HEADER_RE" | head -n 1)
            ;;
        "Credential connection string")
            value=$(printf '%s\n' "$content" | LC_ALL=C grep -aoE -- "$CONNECTION_RE" | head -n 1)
            ;;
        "Credential assignment"|"Generic credential")
            value=$(printf '%s\n' "$content" | LC_ALL=C grep -aioE -- '([A-Za-z0-9_.-]*(password|passwd|pwd|passphrase|secret|token|credential|api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token)[A-Za-z0-9_.-]*)[[:space:]]*[:=][[:space:]]*["'\'']?[^[:space:]"'\'']{4,}' | head -n 1)
            ;;
        "Private key")
            value="$content"
            ;;
        *)
            value="$content"
            ;;
    esac

    [[ -n "$value" ]] || value="$content"
    printf '%s' "$value"
}

is_duplicate_finding() {
    local rule="$1" line="$2" value key
    value=$(extract_finding_value "$rule" "$line")
    key="${rule}|${value}"

    if [[ -n "${SEEN_FINDINGS[$key]+x}" ]]; then
        return 0
    fi

    SEEN_FINDINGS["$key"]=1
    return 1
}

print_finding() {
    local severity="$1" rule="$2" file="$3" line="$4"
    printf '\n[%s] %s\n' "$severity" "$rule"
    printf 'File: %s\n' "$file"
    printf '%s\n' "$line"
}

scan_regex() {
    local severity="$1" rule="$2" regex="$3" file="$4"
    local stream_type="$5" filter_placeholders="${6:-false}"
    local matches line

    case "$stream_type" in
        normal)
            matches=$(LC_ALL=C grep -aEin -m 10 -- "$regex" "$file" 2>/dev/null || true)
            ;;
        gzip)
            matches=$(gzip -cd -- "$file" 2>/dev/null |
                LC_ALL=C grep -aEin -m 10 -- "$regex" || true)
            ;;
    esac

    [[ -n "$matches" ]] || return 0

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        if [[ "$filter_placeholders" == true ]] && is_placeholder_line "$line"; then
            continue
        fi
        if is_duplicate_finding "$rule" "$line"; then
            continue
        fi
        print_finding "$severity" "$rule" "$file" "$line"
    done < <(printf '%s\n' "$matches" | awk '!seen[$0]++')
}

scan_high_confidence() {
    local file="$1" stream_type="$2"
    scan_regex "HIGH" "Private key" "$PRIVATE_KEY_RE" "$file" "$stream_type"
    scan_regex "HIGH" "Credential connection string" "$CONNECTION_RE" "$file" "$stream_type"
    scan_regex "HIGH" "AWS access key" "$AWS_ACCESS_KEY_RE" "$file" "$stream_type"
    scan_regex "HIGH" "GitHub token" "$GITHUB_TOKEN_RE" "$file" "$stream_type"
    scan_regex "HIGH" "Authorization header" "$AUTH_HEADER_RE" "$file" "$stream_type"
}

scan_medium_confidence() {
    local file="$1" stream_type="$2"
    scan_regex "MEDIUM" "JWT" "$JWT_RE" "$file" "$stream_type"
    scan_regex "MEDIUM" "Credential assignment" "$STRICT_CREDENTIAL_RE" "$file" "$stream_type" true
}

scan_low_confidence() {
    local file="$1" stream_type="$2"
    scan_regex "LOW" "Generic credential" "$GENERIC_CREDENTIAL_RE" "$file" "$stream_type" true
}

scan_normal_file() {
    local file="$1"
    scan_high_confidence "$file" normal
    scan_medium_confidence "$file" normal
    $SHOW_LOW && scan_low_confidence "$file" normal
}

scan_log_file() {
    local file="$1" stream_type="normal"
    [[ "$file" == *.gz ]] && stream_type="gzip"
    scan_high_confidence "$file" "$stream_type"
    scan_medium_confidence "$file" "$stream_type"
    $SHOW_LOW && scan_low_confidence "$file" "$stream_type"
}

matches_filtered() {
    local file="$1" basename filename extension
    basename="${file##*/}"
    for filename in "${FILENAMES[@]}"; do
        [[ "$basename" == "$filename" ]] && return 0
    done
    for extension in "${EXTENSIONS[@]}"; do
        [[ "$basename" == *."$extension" ]] && return 0
    done
    return 1
}

matches_log_pattern() {
    local file="$1" basename pattern
    basename="${file##*/}"
    for pattern in "${LOG_PATTERNS[@]}"; do
        [[ "$basename" == $pattern ]] && return 0
    done
    return 1
}

scan_all_mode() {
    local roots=("${ROOTS[@]}") file
    (("${#roots[@]}" > 0)) || roots=("/")
    while IFS= read -r -d '' file; do
        [[ -r "$file" ]] || continue
        is_excluded "$file" && continue
        scan_normal_file "$file"
    done < <(find "${roots[@]}" -type f -readable -print0 2>/dev/null)
}

scan_filtered_mode() {
    local file size
    while IFS= read -r -d '' file; do
        is_excluded "$file" && continue
        matches_filtered "$file" || continue
        size=$(stat -c '%s' -- "$file" 2>/dev/null || echo 0)
        ((size <= MAX_SIZE)) || continue
        scan_normal_file "$file"
    done < <(find "${SCAN_PATHS[@]}" -type f -readable -print0 2>/dev/null)
}

scan_logs_mode() {
    local roots=("${ROOTS[@]}") file
    (("${#roots[@]}" > 0)) || roots=("${LOG_PATHS[@]}")
    while IFS= read -r -d '' file; do
        [[ -r "$file" ]] || continue
        matches_log_pattern "$file" || continue
        scan_log_file "$file"
    done < <(find "${roots[@]}" -type f -readable -print0 2>/dev/null)
}

case "$MODE" in
    all) scan_all_mode ;;
    filtered) scan_filtered_mode ;;
    logs) scan_logs_mode ;;
esac
