# CredHunter

> [!WARNING]
> **AI-coded project:** CredHunter is developed with the assistance of generative AI. The code may contain bugs, false positives, false negatives, or unexpected behavior. Review and test the code before relying on it in security-sensitive environments.

CredHunter is a lightweight, read-only Bash utility for discovering credentials and secret material in files on Linux systems.

It is intended for authorized security assessments, CTF/lab environments, incident response, and system auditing where a fast credential-focused filesystem review is useful without installing a larger framework.

> **Use only on systems you own or are explicitly authorized to assess.** Findings may contain live credentials and other sensitive data. Handle output accordingly.

## Features

CredHunter provides three scanning modes:

- **`filtered`** — targets high-value directories and credential-relevant file types.
- **`all`** — scans readable regular files beneath one or more paths while excluding common virtual/noisy trees.
- **`logs`** — scans log files, including rotated and gzip-compressed logs.

Findings are classified as **HIGH**, **MEDIUM**, or **LOW** confidence. LOW-confidence generic matches are disabled by default to reduce noise.

Current detection includes:

- PEM private-key headers
- Credentials embedded in common connection URIs
- AWS access-key identifiers
- GitHub token formats
- Basic/Bearer Authorization headers
- JWT-like values
- Password, API-key, client-secret, and token assignments
- Broader generic credential assignments with `--show-low`

Other characteristics include read-only operation, no external config file, null-delimited filename handling, placeholder suppression, per-file/per-rule duplicate suppression, gzip log streaming, and configurable arrays directly in the script.

## Requirements

CredHunter targets Linux systems with Bash and common GNU/Linux utilities:

```text
bash
find
grep
awk
stat
tr
```

Compressed log scanning additionally requires:

```text
gzip
```

No Python, package installation, or third-party dependency is required.

## Installation

```bash
git clone https://github.com/akorb90/CredHunter.git
cd CredHunter
chmod +x credhunt.sh
./credhunt.sh --help
```

## Quick start

Recommended progression:

```bash
./credhunt.sh filtered
./credhunt.sh logs
./credhunt.sh all /
```

Increase sensitivity only when required:

```bash
./credhunt.sh filtered --show-low
./credhunt.sh all / --show-low
```

## Usage

```text
credhunt.sh filtered [--show-low]
credhunt.sh all [PATH...] [--show-low]
credhunt.sh all / --really-all [--show-low]
credhunt.sh logs [PATH...] [--show-low]
```

### filtered mode

Filtered mode searches the directories configured in `SCAN_PATHS`, but only scans files whose exact names or extensions match the configured candidate lists.

```bash
./credhunt.sh filtered
```

This is the recommended first scan because it focuses on locations and file types more likely to contain credentials while avoiding much of the noise produced by filesystem-wide searches.

Default roots:

```text
/etc
/home
/opt
/var/www
/srv
/root
```

Candidate filenames include:

```text
.env
.netrc
.pgpass
.my.cnf
.npmrc
.pypirc
.git-credentials
.bash_history
.zsh_history
.python_history
.mysql_history
.psql_history
wp-config.php
application.properties
docker-compose.yml
docker-compose.yaml
```

Candidate extensions include common configuration, source, infrastructure, and text formats such as `.conf`, `.ini`, `.env`, `.yaml`, `.json`, `.php`, `.py`, `.sh`, `.tf`, `.sql`, and `.txt`.

Filtered mode applies `MAX_SIZE`, which currently defaults to 2 MiB per candidate file.

### all mode

All mode recursively searches readable regular files:

```bash
./credhunt.sh all /
```

Multiple roots can be supplied:

```bash
./credhunt.sh all /home /etc /opt /var/www
```

If no path is supplied, `/` is used.

Normal `all` mode deliberately excludes virtual filesystems and common high-noise trees. Default exclusions include:

```text
/proc
/sys
/dev
/run
/usr/share/doc
/usr/share/man
/usr/share/locale
/var/cache
node_modules
vendor
.cache
__pycache__
.git/objects
.git/pack
```

Disable these exclusions with:

```bash
./credhunt.sh all / --really-all
```

This may be extremely noisy and slow.

### logs mode

Log mode searches configured log paths:

```bash
./credhunt.sh logs
```

The default root is `/var/log`. Custom roots override the defaults:

```bash
./credhunt.sh logs /var/log /opt/application/logs
```

CredHunter recognizes conventional `.log` files, rotated logs, gzip-compressed logs, and common Linux log names including `auth.log`, `syslog`, `messages`, `secure`, `daemon.log`, and `kern.log`.

Files ending in `.gz` are streamed through `gzip -cd`; they are not extracted to disk.

## Options

### --show-low

Enables LOW-confidence generic credential matching:

```bash
./credhunt.sh filtered --show-low
```

```bash
./credhunt.sh all / --show-low
```

This broadens keywords to include terms such as `secret`, `token`, `credential`, and `pwd`. It increases coverage at the cost of false positives.

### --really-all

Disables configured path exclusions in all mode:

```bash
./credhunt.sh all / --really-all
```

Combine both options for the deliberately most exhaustive/noisy scan:

```bash
./credhunt.sh all / --really-all --show-low
```

## Confidence levels

### HIGH

HIGH-confidence rules identify strongly structured secret material:

| Rule | Detects |
| --- | --- |
| Private key | PEM private-key headers |
| Credential connection string | Service/database URI containing username and password |
| AWS access key | AWS access-key identifier format |
| GitHub token | Known GitHub token prefixes |
| Authorization header | Basic or Bearer authorization values |

A HIGH finding still requires manual validation. Confidence describes how strongly text resembles secret material; it does not prove a credential is active.

### MEDIUM

MEDIUM currently includes:

- JWT-like values
- Explicit credential assignments such as `password=...`, `client_secret=...`, `api_key=...`, access tokens, and refresh tokens

Placeholder filtering is applied to credential assignments.

### LOW

LOW rules are opt-in via `--show-low` and use broader credential keywords. They are intended for deeper follow-up scans where additional false positives are acceptable.

## Noise reduction

Credential hunting becomes unusable when generic expressions are applied indiscriminately to an entire Linux filesystem. CredHunter uses several controls to reduce this.

**Path exclusions:** virtual filesystems and known noisy content trees are skipped during normal scans.

**Candidate classification:** filtered mode requires an interesting exact filename or extension before scanning contents.

**Placeholder filtering:** common example values such as `password`, `changeme`, `example`, `test`, `dummy`, `null`, `undefined`, `xxxxxxxx`, `your_password`, and `your_secret` are suppressed for applicable rules. Environment/template references are also filtered.

**LOW findings are opt-in:** broad generic rules run only with `--show-low`.

**Match limits:** each rule returns at most ten matches from an individual file, preventing a single noisy file from flooding the output indefinitely.

**Deduplication:** identical output lines from the same file/rule are emitted once.

## Output

A finding resembles:

```text
[MEDIUM] Credential assignment
File: /path/to/application.conf
42:password=<matched-value>
```

Output contains confidence, rule, file, line number, and matching line.

> Current output can expose the complete matched line and therefore potentially a live secret on screen, in terminal logging, or in redirected output. Treat scan results as sensitive.

## Running directly with curl

CredHunter can be streamed into Bash without saving the script:

```bash
curl -fsSL https://raw.githubusercontent.com/akorb90/CredHunter/main/credhunt.sh | bash -s -- filtered
```

Arguments after `bash -s --` become arguments to CredHunter.

Examples:

```bash
curl -fsSL https://raw.githubusercontent.com/akorb90/CredHunter/main/credhunt.sh | bash -s -- logs
```

```bash
curl -fsSL https://raw.githubusercontent.com/akorb90/CredHunter/main/credhunt.sh | bash -s -- all /home /etc /opt
```

```bash
curl -fsSL https://raw.githubusercontent.com/akorb90/CredHunter/main/credhunt.sh | bash -s -- filtered --show-low
```

Piping remote code directly into a shell is convenient but carries supply-chain risk. For higher-assurance use, download and inspect or pin the script first.

## Configuration

Configuration is embedded in `credhunt.sh`; no separate configuration file is required.

### MAX_SIZE

```bash
MAX_SIZE=2097152
```

Maximum candidate size in bytes for filtered mode.

### SCAN_PATHS

Controls default filtered-mode search roots:

```bash
SCAN_PATHS=(
    "/etc"
    "/home"
    "/opt"
    "/var/www"
    "/srv"
    "/root"
)
```

### EXTENSIONS

Controls extensions accepted by filtered mode. Extensions are specified without a leading dot.

### FILENAMES

Contains exact high-value filenames such as `.env`, `.netrc`, history files, and application configuration names.

### EXCLUDE_PATHS

Contains Bash glob patterns for noisy or undesirable trees:

```bash
EXCLUDE_PATHS=(
    "/proc"
    "/proc/*"
    "*/node_modules/*"
    "*/.git/objects/*"
)
```

### LOG_PATHS

Defines default log roots. Command-line roots override this array.

### LOG_PATTERNS

Controls which filenames inside log roots are considered log files.

### PLACEHOLDERS

Contains known example/default values that should be suppressed from applicable generic credential findings.

## Detection rules

Regular expressions are defined near the top of the script:

```text
PRIVATE_KEY_RE
CONNECTION_RE
AWS_ACCESS_KEY_RE
GITHUB_TOKEN_RE
AUTH_HEADER_RE
JWT_RE
STRICT_CREDENTIAL_RE
GENERIC_CREDENTIAL_RE
```

They are grouped by:

```text
scan_high_confidence
scan_medium_confidence
scan_low_confidence
```

This makes additional provider-specific patterns straightforward to add while assigning an appropriate confidence level.

CredHunter invokes `grep` with an explicit `--` before regex arguments so patterns beginning with a hyphen, such as PEM headers, cannot be interpreted as command-line options.

## Recommended workflow

Start targeted:

```bash
./credhunt.sh filtered
```

Then inspect logs:

```bash
./credhunt.sh logs
```

Then broaden filesystem coverage:

```bash
./credhunt.sh all /
```

If coverage appears too restrictive:

```bash
./credhunt.sh filtered --show-low
./credhunt.sh all / --show-low
```

Use `--really-all` only when the additional noise and runtime are acceptable.

For focused investigations, explicit roots are preferable:

```bash
./credhunt.sh all /home /opt /var/www
```

## Permissions

CredHunter does not bypass filesystem permissions. It scans only files readable by the executing account.

Consequently, results vary with privilege level. Permission errors from filesystem traversal are suppressed to keep output focused on findings.

## Read-only behavior

CredHunter is intended to be non-destructive. It reads metadata and file contents, streams gzip content to standard output, and prints matches.

It does not modify candidate files, change permissions, authenticate using discovered credentials, or delete data.

## Performance

`filtered` is generally fastest because candidate classification occurs before content scanning.

`logs` depends primarily on the size and number of logs.

`all /` can be considerably slower because every readable regular file beneath the selected roots must be considered and multiple rules may be evaluated.

`--show-low` adds an additional generic-rule pass.

`--really-all` can substantially increase runtime and noise.

## Limitations

CredHunter is deliberately small and dependency-light. It is not a replacement for a full secret-scanning platform.

Current limitations:

- Regex detection can produce false positives and false negatives.
- A syntactically valid token may be expired, revoked, fake, or an example.
- Secrets split across multiple lines may not be detected.
- Arbitrary archives are not unpacked.
- Binary-format secret extraction is not implemented.
- Git history is not currently scanned.
- Entropy-based generic secret detection is not currently implemented.
- Process environments under `/proc` are not currently inspected by a dedicated scanner.
- Structured JSON/TSV output is not currently available.
- Secrets are currently displayed rather than redacted.
- Global cross-file deduplication is not currently performed.
- CredHunter does not validate or attempt to use discovered credentials.

## Security considerations

Credential-discovery output is sensitive. Avoid saving results to world-readable files, shared terminal logs, or other locations where unauthorized users may gain access.

If results must be retained during an authorized assessment, protect them appropriately.

Remote execution via `curl | bash` means trusting the content returned by the URL at execution time. Inspecting or pinning a known revision provides stronger assurance.

## Roadmap

Potential future improvements include:

- Additional provider-specific secret patterns
- Entropy-assisted generic secret detection
- Dedicated high-value Linux credential-location checks
- Controlled process-environment inspection
- Git working-tree and history scanning
- Global finding deduplication
- Structured JSON/TSV output
- Optional secret redaction
- Severity/confidence tuning
- Archive inspection
- Baseline/diff support

## Contributing

Issues and pull requests are welcome.

For a new detection rule, useful information includes the secret family, a safe synthetic example, expected confidence level, likely false-positive sources, and placeholder patterns that should be suppressed.

**Never submit live credentials, tokens, private keys, or other secrets in issues, pull requests, test fixtures, or examples.**

## License

CredHunter is licensed under the GNU General Public License v3.0. See the repository license for the full terms.
