# Contributing to ransomware-ir-playbook

Thank you for your interest in contributing! This playbook is a living document — real-world IR experience, new ransomware IoCs, and automation improvements are always welcome.

## How to Contribute

### 1. Fork & Clone
```bash
git clone https://github.com/r0ms3c/ransomware-ir-playbook.git
cd ransomware-ir-playbook
git checkout -b feature/your-improvement
```

### 2. Types of Contributions Welcome

| Type | Examples |
|------|---------|
| 🦠 New IoCs | Ransomware signatures, C2 patterns, file extensions |
| 🔧 Script improvements | Bug fixes, new detection logic, performance |
| 🔍 SIEM rules | Splunk, Elastic, QRadar, Microsoft Sentinel |
| 📖 Documentation | Procedure improvements, new scenarios |
| 🧪 Tests | Script validation, Ansible molecule tests |

### 3. Standards

- **Bash scripts:** Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html). Use `set -euo pipefail`.
- **Python:** PEP 8 compliant. Type hints where practical. Python 3.8+ compatible.
- **Ansible:** YAML lint clean. Use FQCNs (`ansible.builtin.*`). No hardcoded credentials.
- **Documentation:** Markdown. Keep procedures actionable and specific.

### 4. IoC Submissions

When submitting new IoCs, include:
- Source / threat intel reference
- Date first observed
- Associated ransomware family
- Confidence level (High / Medium / Low)

### 5. Pull Request Process

1. Ensure your branch is up to date with `main`
2. Test scripts in a safe, isolated environment
3. Update relevant documentation
4. Submit PR with a clear description of what changed and why

### 6. Responsible Use

This project is for **defensive security only**. Contributions that could enable offensive use will be rejected.

## Code of Conduct

Be professional, constructive, and respectful. This is a security community resource.
