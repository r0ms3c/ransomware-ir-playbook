### 🔴 Ransomware Incident Response Playbook
#### Ubuntu Linux — All Environments


---

> **A production-grade, fully automated Incident Response framework for ransomware attacks on Ubuntu Linux servers. Covers Detection → Containment → Eradication → Recovery with battle-tested scripts, Ansible automation, and forensic tooling.**

---



## 🎯 Overview

This repository provides a **complete operational playbook** for responding to ransomware incidents on Ubuntu Linux servers, purpose-built for banking and financial services organizations where:

- **Systems run on Ubuntu** (18.04 LTS through 24.04 LTS)
- **Regulatory requirements** demand documented, reproducible response procedures
- **RTO/RPO commitments** require automation — not manual step-by-step recovery
- **Forensic evidence** must be preserved for legal and compliance obligations



## 🗂 Repository Structure (IN DEV PROCESS ...)

```
ransomware-ir-playbook/
│
├── README.md                          # This file
├── CONTRIBUTING.md                    # Contribution guidelines
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
│       └── roles/
│           └── ubuntu_hardening/      # Reusable hardening role
│
├── templates/
│   ├── incident-ticket.md             # Incident tracking template
│   ├── pir-report.md                  # Post-Incident Review template
│   ├── regulatory-notification.md     # Regulator notification template
│   └── chain-of-custody.md            # Forensic evidence log
│
└── ...
   
```

---

## ⚡ Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/r0ms3c/ransomware-ir-playbook.git
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




## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Areas where contributions are especially valuable:
- Additional ransomware family IoC signatures
- SIEM-specific detection rules (Splunk, Elastic, QRadar)
- Container/Kubernetes variants
- Ansible automation

---

## ⚠️ Disclaimer

> This repository is intended for **authorized security professionals** responding to incidents on systems they have explicit permission to access. All scripts must only be used on systems you own or have written authorization to test. The authors are not responsible for misuse of the tools or procedures contained herein.
>
> Ransom payment decisions involve complex legal, regulatory, and ethical considerations. Always consult Legal counsel before engaging with threat actors.

---

<div align="center">

**Built for the security community by a security engineer.**

⭐ If this helped you, please star the repo — it helps others find it.

</div>

