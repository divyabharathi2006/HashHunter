# HashHunter — Local Hash Audit Dashboard

HashHunter is an authorized-use-only, loopback-hosted dashboard for bounded candidate verification against hashes you own or have explicit permission to assess. It makes no external requests, and does not attempt account access or network authentication. Existing FastAPI routes and vanilla-JS dashboard are retained.

> **Authorization:** Use only for hashes you own or are explicitly authorized to test. The checkbox is required for each job; it is not a substitute for legal or organizational approval.

## Install and run

Python 3.10+ is recommended (the project is tested with the selected local Python environment). Runtime dependencies include FastAPI/Uvicorn, `argon2-cffi` 25.1.0, `bcrypt` 4.3.0, and `pycryptodome` 3.23.0. PyCryptodome supplies MD4 because modern OpenSSL/Python builds do not consistently expose it.

### Windows PowerShell

```powershell
cd "D:\Project 12"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### Linux / macOS

```sh
cd "/path/to/Project 12"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Keep the bind address at `127.0.0.1`; do not expose the dashboard to a network. Run tests with `python -m pytest -q`.

## Verified formats

The following formats have candidate verifiers in this app. “Detected” means syntax/family recognition only; it does not imply the format can be verified.

| Format | Candidate encoding and computation | Limits / notes |
| --- | --- | --- |
| Raw MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | Hex; UTF-8 candidate bytes | Raw digest lengths are ambiguous for 32, 56, 64, 96, and 128 hex characters. Select algorithm manually for those lengths. SHA-1's 40-character length is unique within this registry but remains a heuristic. |
| Raw SHA3-224/256/384/512 | Hex; UTF-8 candidate bytes; Python `hashlib` | Shared output lengths with SHA-2 require manual selection. |
| NTLM | 32-hex digest; MD4 of candidate encoded as UTF-16LE | Separate explicit algorithm selection; never inferred as NTLM vs MD5. NTLM has no salt; configured salt is rejected. |
| bcrypt `$2a$`, `$2b$`, `$2y$` | Modular crypt string; UTF-8 candidate bytes | Cost 4–12 only. Inputs over bcrypt's 72-byte effective limit are not evaluated (no silent truncation). |
| Argon2id/i/d PHC, version 19 | `$argon2{variant}$v=19$m=...,t=...,p=...$salt$hash`; PHC base64 | Memory 8–32,768 KiB, time 1–3, parallelism 1–8, salt 8–64 bytes, output 16–64 bytes, memory at least `8*p` KiB. |
| HashHunter scrypt PHC subset | `$scrypt$ln=...,r=...,p=...$salt$derived`; standard base64 (padding optional) | `ln` 10–20, `r` 1–16, `p` 1–8; calculated memory limited to 32 MiB; salt 8–64 bytes; derived output 16–64 bytes. This is a deliberately narrow Passlib-style parameter subset, not every scrypt string. |
| Django PBKDF2-SHA256 | `pbkdf2_sha256$iterations$salt$base64-digest`; UTF-8 candidate, UTF-8 salt | 1–500,000 iterations and 32-byte digest only. |

Structured formats carry their own salts and parameters; the raw salt controls do not modify them. For raw hashes only, an optional explicit salt is UTF-8 encoded and prepended/appended as selected. The legacy `algorithm$salt$digest` TXT input is a HashHunter convention: it means the named raw digest and prepends UTF-8 salt bytes. It is not a standard password-hash format.

### Recognized but not verified / unsupported

- Unix modular crypt `$1$` (md5crypt), `$5$` (sha256crypt), and `$6$` (sha512crypt) are identified as unsupported. Python's `crypt` availability/behavior is not portable across Windows and Linux, so HashHunter does not claim support.
- Passlib `$pbkdf2-sha256$...`, other PBKDF2 encodings (including Django PBKDF2-SHA1), bcrypt costs outside the safe range, other bcrypt variants, non-v19 Argon2 PHC strings, malformed encodings, and scrypt strings outside the documented subset are not verified.
- Other formats such as LDAP `{SSHA}`, MySQL, PostgreSQL, Cisco, and application-specific encodings are unsupported. A prefix or length resemblance is not treated as verified support.
- Raw SHA-family hexadecimal detection is only a hint. Algorithms with equal digest lengths are reported as ambiguous; the backend rejects those raw inputs until a selection is supplied. NTLM is always explicit.

## Input and candidate limits

- TXT accepts one raw/structured hash per line; blank lines and `#` comment lines are ignored. Up to 5,000 targets and 512 KiB input.
- CSV requires an exact `digest` header. An optional exact `algorithm` header is available for ambiguous raw digests; the UI's explicit algorithm selector overrides the CSV value. Import remains in browser memory.
- Duplicate targets are identified in task status. In a mixed batch, malformed or unsupported rows are marked `INVALID FORMAT` while valid targets continue; each target reports `pending`, `matched`, `not_matched`, `not_tested_limit`, `cancelled`, `error`, or `invalid_format`. A batch containing no valid target is rejected with line-specific parse reasons.
- Dictionary mode streams a UTF-8 wordlist (2 MiB / 250,000 line maximum) and optional small common-candidate transforms. Mask mode generates lazily (`?l`, `?u`, `?d`, `?s`, `?a`, `?c`). Manual mode checks exactly one entered candidate.
- Candidate ceiling defaults to 250,000 and is capped at 1,000,000. A bounded pool of at most two threads is used for job orchestration; this is **not** a claim of CPU parallelism. Work is cooperative for pause/resume/cancel.
- To bound intentionally slower encoded KDF work, non-manual jobs containing any structured password-hash target are capped at 100 candidates per task (the API reports the effective cap). Each encoded format also has the work-factor limits in the table above.
- The current candidate is intentionally never streamed or displayed. Plaintext appears only after a successful verifier match. Export Results CSV is an explicit browser download initiated by the user and includes verified candidate values; the server itself does not persist it.

## Demo and sample vectors

The demo button creates a local SHA-256 digest for the built-in training word `password`. It is a deliberately weak demo, not a secure credential. Tests create their own safe vectors locally and do not include user-provided hashes.

## Hashing is not encryption

Encryption is intended to be reversible with a key. A cryptographic hash is a one-way digest and cannot be decrypted. HashHunter computes the selected verifier for each supplied candidate and compares the result. A match shows only a tested candidate; no match does not establish that the original input is unrecoverable.

## Privacy, limitations, and password-storage advice

- Hashes, candidate lists, and job state remain in process memory; no application database, telemetry, or third-party service is used. Request bodies and recovered values are not logged. State disappears when the process exits.
- A confirmed matching candidate is retained in volatile task state for the results panel and optional user-requested CSV export. Browser downloads, screenshots, crash dumps, extensions, and the operating system are outside the app's in-memory boundary.
- Jobs are bounded and volatile. Shutdown cancels active work and waits for worker threads to stop. This is a local auditing/learning tool, not a general-purpose recovery product.
- **MD5 and SHA-1 are not suitable for password storage.** SHA-224/256/384/512 and SHA-3 are fast general-purpose digests and are also unsuitable alone. For password storage, prefer Argon2id with a unique random salt and calibrated memory/time costs; scrypt, bcrypt, or PBKDF2-HMAC can be appropriate alternatives when configured and maintained correctly. Never invent or reuse salts/work factors based on this tool.
