# Ransomware IR — Triage Overview

## ✅ PHASE 1 — System Identity  
**File:** `volatile/system_info.txt`

**What it includes:**  
- Hostname, OS, kernel version  
- Uptime (detect unexpected reboot)  
- Logged‑in users  
- Environment variables  

**Look for:**  
- Strange environment values (`LD_PRELOAD`, suspicious PATH entries)  
- Unexpected active sessions  
- Very short uptime before detection  

---

## 🧠 PHASE 2 — Processes  
**Files:** `processes/*.txt`

**What it includes:**  
- `ps auxef`, `pstree`  
- Top CPU/MEM processes  
- lsof summary  
- **PID → Executable mapping**  
- **SUSPICIOUS_PROCESSES.txt** (deleted/memfd/tmp binaries)

**Look for:**  
- Processes running from `/tmp`, `/dev/shm`, `(deleted)`  
- Unusual CPU spikes  
- Children of Office applications  
- Command‑line obfuscation  

---

## 🌐 PHASE 3 — Network  
**File:** `network/network_state.txt`

**What it includes:**  
- Listening ports  
- Active outbound connections  
- DNS statistics  
- Interface/ARP/route tables  

**Look for:**  
- Unknown listeners  
- Unexpected external IP connections  
- DNS queries to suspicious domains  

---

## 🔐 PHASE 4 — Authentication Logs  
**File:** `auth/auth_events.txt`

**What it includes:**  
- SSH accepted/failed logins  
- `sudo` command usage  
- UID 0 accounts  
- sudo/wheel group members  

**Look for:**  
- Failed login bursts  
- Successful logins from unusual IPs  
- Users gaining sudo unexpectedly  

---

## 🗂 PHASE 5 — Filesystem IOCs  
**File:** `filesystem/filesystem_iocs.txt`

**What it includes:**  
- Ransom notes  
- Encrypted extensions  
- Recently modified files  
- Mounted filesystems  

**Look for:**  
- New extensions: `.enc`, `.locked`, `.encrypted`, `.pay`, `.ransom`  
- Large clusters of recent file changes  
- Notes inside non‑user directories  

---

## 🕒 PHASE 6 — Persistence  
**File:** `scheduled/scheduled_tasks.txt`

**What it includes:**  
- root/system/user crontabs  
- Cron.d contents  
- systemd services  
- rc.local  
- SSH authorized_keys  

**Look for:**  
- Cron entries pointing to `/tmp` or unknown scripts  
- Newly added systemd services  
- Unexpected SSH keys  

---

## 🧩 PHASE 7 — Kernel & Modules  
**File:** `kernel/kernel_state.txt`

**What it includes:**  
- Loaded kernel modules  
- `/etc/ld.so.preload`  
- Shared library paths  
- AppArmor / SELinux status  

**Look for:**  
- Unknown kernel modules  
- Suspicious entries in `ld.so.preload`  
- Disabled SELinux/AppArmor  

---

## 🔏 PHASE 8 — Chain of Custody  
**File:** `CHAIN_OF_CUSTODY.sha256`

**What it includes:**  
- SHA256 hash of every generated file  
- Ensures evidence integrity  

**Look for:**  
- Hash mismatches (if re‑hashed later)  

---

## 📄 PHASE 9 — Summary  
**File:** `TRIAGE_SUMMARY.txt`

**What it includes:**  
- Findings overview  
- Ransom note count  
- Suspicious process count  
- Next steps for the analyst  

**Primary actions:**  
1. Review suspicious processes  
2. Review filesystem IOCs  
3. If ransomware confirmed → run isolate.sh  
4. Perform full forensic capture  

---

# 🚨 Quick Decision Flow for Analysts
1. Open TRIAGE_SUMMARY.txt
2. If suspicious_processes > 0 → inspect SUSPICIOUS_PROCESSES.txt
3. If ransom_notes > 0 → inspect filesystem_iocs.txt
4. Check network_state.txt for C2 indicators
5. Check auth_events.txt for unauthorized access
6. If ransomware indicators confirmed → isolate host immediately

