# poc-codex-sec

> ⚠️ **WARNING – Intentionally Vulnerable Code**
> This repository contains **deliberately insecure** code created to demonstrate and test CodeQL / Codex Security scanning.
> **Never deploy any of these files in a real environment.**

---

## Purpose

Demonstrate how [GitHub CodeQL](https://codeql.github.com/) (Codex Security) detects common vulnerability classes across multiple languages.

---

## Repository Structure

```
poc-codex-sec/
├── python/
│   ├── app.py           # Vulnerable Flask application
│   └── requirements.txt
├── javascript/
│   ├── app.js           # Vulnerable Express application
│   └── package.json
└── java/
    └── src/main/java/com/example/
        └── VulnerableApp.java
```

---

## Intentional Vulnerabilities

| # | Vulnerability | Language(s) | CWE |
|---|--------------|-------------|-----|
| 1 | **SQL Injection** | Python, JavaScript, Java | CWE-89 |
| 2 | **OS Command Injection** | Python, JavaScript, Java | CWE-78 |
| 3 | **Path Traversal** | Python, JavaScript, Java | CWE-22 |
| 4 | **Server-Side Request Forgery (SSRF)** | Python | CWE-918 |
| 5 | **Reflected XSS / Template Injection** | Python, JavaScript | CWE-79 |
| 6 | **Insecure Deserialization** | Python (`pickle`), JavaScript (`eval`), Java | CWE-502 |
| 7 | **Hardcoded Credentials / Secrets** | Python, JavaScript, Java | CWE-798 |
| 8 | **Weak Cryptography (MD5)** | Python, Java | CWE-327 |
| 9 | **Open Redirect** | Python, JavaScript | CWE-601 |
| 10 | **Prototype Pollution** | JavaScript | CWE-1321 |
| 11 | **XXE Injection** | Java | CWE-611 |
| 12 | **Code Injection via eval()** | JavaScript | CWE-94 |

---

## Running a CodeQL Scan

```bash
# Install the CodeQL CLI
# https://github.com/github/codeql-cli-binaries/releases

# Create a database for Python
codeql database create python-db --language=python --source-root=python/

# Analyse with the security suite
codeql database analyze python-db \
  codeql/python-queries:codeql-suites/python-security-and-quality.qls \
  --format=sarif-latest \
  --output=python-results.sarif

# Repeat for JavaScript / Java
```

You can also enable **GitHub Advanced Security** on this repository and let GitHub Actions run the scans automatically via the default CodeQL workflow.
