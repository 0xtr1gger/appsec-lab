# AppSec Lab
Interactive, hands-on OWASP Top 10 AppSec lab.
Intentionally vulnerable functionality with source code and practical mitigation examples. Exploit real bugs, then learn how to fix them.

>The application contains intentionally vulnerable code for educational and demonstration purposes.

Built with Python & Flask and Bootstrap ❤︎⁠

<img width="913" height="1004" alt="appsec-lab-sqli" src="https://github.com/user-attachments/assets/a688806a-3b48-425a-b110-82cb12c53aa7" />


## Quick Start

### Prerequisites

- Python 3.8+
- pip package manager

### Installation

- Clone the repository:

```bash
git clone https://github.com/0xtr1gger/appsec-lab.git
cd appsec-lab
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```
python app.py
```


### Access the Lab

- Open your browser and navigate to: `http://localhost:5000`


## Current Vulnerabilities

| Vulnerability | CWE | Status | Link to blog |
|---------------|-----|--------|-------------|
| SQL Injection (SQLi) | CWE-89 | ✅ Complete | [SQL injection](https://0xtr1gger.github.io/trigger_book/Hack-the-Web/Injection/SQLi/SQL-injection) |
| OS Command Injection | CWE-78 | ✅ Complete | [OS command injection](https://0xtr1gger.github.io/trigger_book/Hack-the-Web/Injection/OS-command-injection) |

## How to Use

1. **Learn**
    -  Learn how each vulnerability works and what impact it can have. Read in-depth articles in my [0xtr1gger book](https://0xtr1gger.github.io/trigger_book/).

2. **Exploit**

    - Switch to the **`Vulnerable`** tab and exaperiment with actual exploitation payloads against live, intentionally insecure functionality. Inspect the source code and read explanations to understand the root cause of the vulnerability.

3. **Fix**
    - Switch to the **`Secure`** tab to see secure version of the code and understand exactly what changed. Interact with live functionality to see the difference.

## Planned vulnerabilities

- [ ] Cross-Site Scripting (XSS) - CWE-79
- [ ] File Upload - CWE-434
- [ ] Insecure Direct Object References (IDOR) - CWE-639
- [ ] Server-Side Template Injection (SSTI) - CWE-94
- [ ] XML External Entity (XXE) Injection - CWE-611
- [ ] Path Traversal - CWE-22
- [ ] Insecure Deserialization - CWE-502

Other TODOs:
- Sample GitHub Actions CI/CD to detect vulnerabilities ~~(though no one will actually fix them! — unless what is supposed to be "`Secure`" is actually vulnerable)~~


## Contributing

We welcome contributions! Here's how you can help:

**Reporting Issues:**

- Use GitHub Issues to report bugs or request features
- Include steps to reproduce the issue
- Provide environment information (OS, Python version, browser)

**Submitting Vulnerabilities:**

1. Fork the repository
2. Create a feature branch for your vulnerability
3. Follow the project structure and coding standards
4. Add documentation and examples
5. Submit a pull request

Please, test before PR!


>P.S. **`Secure`** sections must actually be secure...

