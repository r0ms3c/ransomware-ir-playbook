### 🔴 Ransomware Incident Response Playbook
#### Ubuntu Linux — All Environments


---

> **A production-grade, fully automated Incident Response framework for ransomware attacks on Ubuntu Linux servers. Covers Detection → Containment → Eradication → Recovery with battle-tested scripts, Ansible automation, and forensic tooling.**

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Repository Structure](#-repository-structure)
- [Quick Start](#-quick-start)
- [Playbook Phases](#-playbook-phases)
- [Scripts Reference](#-scripts-reference)
- [Ansible Automation](#-ansible-automation)
- [Regulatory Compliance](#-regulatory-compliance)
- [Prerequisites](#-prerequisites)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)

---

## 🎯 Overview

This repository provides a **complete operational playbook** for responding to ransomware incidents on Ubuntu Linux servers, purpose-built for banking and financial services organizations where:

- **Systems run on Ubuntu** (18.04 LTS through 24.04 LTS)
- **Regulatory requirements** demand documented, reproducible response procedures
- **RTO/RPO commitments** require automation — not manual step-by-step recovery
- **Forensic evidence** must be preserved for legal and compliance obligations

### What's included

| Component | Description |
|-----------|-------------|
| 📄 [Playbook Docs](docs/) | Full phase-by-phase procedures (Detection → Recovery) |
| 🔧 [Bash Scripts](scripts/bash/) | Triage, isolation, forensic capture, IOC scanning |
| 🐍 [Python Tools](scripts/python/) | Forensic analyzer, IOC hunter, timeline builder, report generator |
| ⚙️ [Ansible Playbooks](scripts/ansible/) | Automated isolation, hardening, and recovery automation |
| 📝 [Templates](templates/) | Incident ticket, PIR report, regulatory notification |
| 🏗️ [Diagrams](diagrams/) | Architecture, decision trees, response flowcharts |

---

## 🗂 Repository Structure

```
ransomware-ir-playbook/
│
├── README.md                          # This file
├── CONTRIBUTING.md                    # Contribution guidelines
├── LICENSE                            # MIT License
│
├── docs/                              # Full playbook documentation
│   ├── 00-overview.md                 # Purpose, scope, severity matrix
│   ├── 01-detection.md                # IoCs, detection sources, triage commands
│   ├── 02-containment.md              # Isolation procedures, evidence preservation
│   ├── 03-eradication.md              # Malware removal, persistence hunting
│   ├── 04-recovery.md                 # Backup validation, system rebuild
│   ├── 05-communications.md           # Escalation matrix, regulatory notifications
│   ├── 06-post-incident.md            # PIR, lessons learned, hardening
│   └── 07-hardening-guide.md          # Ubuntu CIS benchmark, hardening checklist
│
├── scripts/
│   ├── bash/
│   │   ├── triage.sh                  # Initial host triage (volatile data capture)
│   │   ├── isolate.sh                 # Network isolation via iptables/UFW
│   │   ├── forensic-capture.sh        # Memory dump + disk image + evidence collection
│   │   ├── ioc-scan.sh                # Scan host for ransomware IoCs
│   │   ├── persistence-hunt.sh        # Hunt for persistence mechanisms
│   │   └── hardening-check.sh         # CIS benchmark compliance checker
│   │
│   ├── python/
│   │   ├── forensic_analyzer.py       # Parse and analyze forensic artifacts
│   │   ├── ioc_hunter.py              # Multi-source IoC correlation engine
│   │   ├── timeline_builder.py        # Attack timeline reconstruction
│   │   └── ir_report_generator.py     # Automated incident report generation
│   │
│   └── ansible/
│       ├── playbooks/
│       │   ├── isolate-host.yml       # Automated host isolation
│       │   ├── collect-forensics.yml  # Fleet-wide forensic collection
│       │   ├── harden-ubuntu.yml      # Ubuntu hardening playbook
│       │   └── restore-system.yml     # Guided system restoration
│       └── roles/
│           └── ubuntu_hardening/      # Reusable hardening role
│
├── templates/
│   ├── incident-ticket.md             # Incident tracking template
│   ├── pir-report.md                  # Post-Incident Review template
│   ├── regulatory-notification.md     # Regulator notification template
│   └── chain-of-custody.md            # Forensic evidence log
│
└── diagrams/
    ├── ir-flowchart.md                # Response decision flowchart (Mermaid)
    └── network-isolation-arch.md      # Isolation architecture diagram (Mermaid)
```

---

## ⚡ Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/ransomware-ir-playbook.git
cd ransomware-ir-playbook
```

### 2. Make scripts executable
```bash
chmod +x scripts/bash/*.sh
```

### 3. Run triage on a suspected host
```bash
# Run as root on the suspected host
sudo bash scripts/bash/triage.sh --output /mnt/forensics/
```

### 4. Isolate a confirmed host
```bash
# Isolate host, keeping management access from IR jumpbox
sudo bash scripts/bash/isolate.sh --mode firewall --mgmt-ip 10.0.100.5
```

### 5. Run fleet-wide IoC scan with Ansible
```bash
cd scripts/ansible
ansible-playbook playbooks/collect-forensics.yml -i inventory/hosts.ini --limit compromised_hosts
```

---

## 📖 Playbook Phases

```
DETECT ──► CONTAIN ──► INVESTIGATE ──► ERADICATE ──► RECOVER ──► IMPROVE
  │            │              │              │             │           │
  ▼            ▼              ▼              ▼             ▼           ▼
IoC Hunt   Isolate        Memory Dump    Persistence   Rebuild     PIR + 
Log Review  Network        Disk Image     Removal       Validate    Hardening
SIEM Alert  Protect        Volatile       Malware ID    Restore     Training
            Backups        Data           Root Cause    Monitor
```

| Phase | Doc | Time Target | Key Scripts |
|-------|-----|-------------|-------------|
| 🔍 Detection | [01-detection.md](docs/01-detection.md) | T+0 to T+15 min | `triage.sh`, `ioc-scan.sh` |
| 🔒 Containment | [02-containment.md](docs/02-containment.md) | T+15 to T+30 min | `isolate.sh`, `forensic-capture.sh` |
| 🔬 Eradication | [03-eradication.md](docs/03-eradication.md) | T+4 to T+24 hrs | `persistence-hunt.sh` |
| 🔄 Recovery | [04-recovery.md](docs/04-recovery.md) | T+24 to T+72 hrs | `restore-system.yml` |
| 📣 Communications | [05-communications.md](docs/05-communications.md) | Throughout | Templates |
| 📊 Post-Incident | [06-post-incident.md](docs/06-post-incident.md) | T+5 days | `ir_report_generator.py` |

---

## 🔧 Scripts Reference

### Bash Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `triage.sh` | Captures volatile data: processes, connections, users, mounts | `sudo ./triage.sh --output /evidence/` |
| `isolate.sh` | Isolates host via UFW/iptables, preserving management access | `sudo ./isolate.sh --mode firewall --mgmt-ip <IP>` |
| `forensic-capture.sh` | Memory dump (LiME), disk image, log archive, chain of custody | `sudo ./forensic-capture.sh --dest /mnt/forensics/` |
| `ioc-scan.sh` | Scans for ransom notes, encrypted files, suspicious processes | `sudo ./ioc-scan.sh --full --output /tmp/ioc_report.txt` |
| `persistence-hunt.sh` | Hunts cron, systemd, SSH keys, backdoor accounts, LD_PRELOAD | `sudo ./persistence-hunt.sh --report` |
| `hardening-check.sh` | CIS Ubuntu Level 2 benchmark compliance check | `sudo ./hardening-check.sh --level 2 --report html` |

### Python Tools

| Script | Purpose | Usage |
|--------|---------|-------|
| `forensic_analyzer.py` | Parses auth logs, audit logs, syslog for attack patterns | `python3 forensic_analyzer.py --logdir /var/log/` |
| `ioc_hunter.py` | Correlates IoCs across multiple hosts and log sources | `python3 ioc_hunter.py --hosts hosts.txt --iocs iocs.json` |
| `timeline_builder.py` | Reconstructs chronological attack timeline from artifacts | `python3 timeline_builder.py --evidence /mnt/forensics/` |
| `ir_report_generator.py` | Generates formatted incident report from collected data | `python3 ir_report_generator.py --incident IR-2024-001` |

### Ansible Playbooks

| Playbook | Purpose |
|----------|---------|
| `isolate-host.yml` | Automates network isolation across multiple hosts simultaneously |
| `collect-forensics.yml` | Fleet-wide forensic artifact collection |
| `harden-ubuntu.yml` | Applies CIS Ubuntu hardening baseline to fresh systems |
| `restore-system.yml` | Guided restoration workflow with validation gates |

---

## ⚙️ Ansible Automation

```bash
# Install Ansible
pip3 install ansible

# Configure your inventory
cp scripts/ansible/inventory/hosts.ini.example scripts/ansible/inventory/hosts.ini
# Edit hosts.ini with your server groups

# Run hardening on a new server
ansible-playbook scripts/ansible/playbooks/harden-ubuntu.yml \
  -i scripts/ansible/inventory/hosts.ini \
  --limit new_servers \
  --ask-become-pass

# Collect forensics from suspected hosts
ansible-playbook scripts/ansible/playbooks/collect-forensics.yml \
  -i scripts/ansible/inventory/hosts.ini \
  --limit compromised_hosts \
  -e "evidence_dest=/mnt/ir-evidence/$(date +%Y%m%d)"
```

---


## 📋 Prerequisites

### On the IR Jumpbox / Analyst Machine
```bash
# Python dependencies
pip3 install -r requirements.txt

# Ansible
pip3 install ansible ansible-lint

# Optional: for report generation
pip3 install jinja2 reportlab
```

### On Target Ubuntu Servers (for full forensics)
```bash
# LiME for memory capture (compile on target)
sudo apt-get install linux-headers-$(uname -r) build-essential git

# Volatility dependencies (on analyst machine)
pip3 install volatility3
```

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Areas where contributions are especially valuable:
- Additional ransomware family IoC signatures
- SIEM-specific detection rules (Splunk, Elastic, QRadar)
- Container/Kubernetes variants

---

## ⚠️ Disclaimer

> This repository is intended for **authorized security professionals** responding to incidents on systems they have explicit permission to access. All scripts must only be used on systems you own or have written authorization to test. The authors are not responsible for misuse of the tools or procedures contained herein.
>
> Ransom payment decisions involve complex legal, regulatory, and ethical considerations. Always consult Legal counsel before engaging with threat actors.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for the security community by a security engineer.**

⭐ If this helped you, please star the repo — it helps others find it.

</div>

