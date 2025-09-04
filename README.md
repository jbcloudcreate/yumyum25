# 🖥️ James' Infra & Home-Lab Scripts

<p align="center">
  <img src="https://img.shields.io/badge/repo-private-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/focus-infra%20%26%20homelab-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/powershell-0078d7?style=flat-square&logo=powershell&logoColor=white" />
  <img src="https://img.shields.io/badge/bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white" />
  <img src="https://img.shields.io/badge/python-3776AB?style=flat-square&logo=python&logoColor=white" />
</p>

---

Welcome to my **script vault** — a central repo where I keep the tools, helpers, and one-off automations that power both my **professional infra projects** and my **personal home-lab**.  

If you’re into **Windows Server, Active Directory, AWS, TrueNAS, Docker, Grafana**, or just making your life easier with a bit of code, you’ll probably find something interesting here.  

---

<p align="center">
  <em>💡 Infra runs better when you script it once, and never type it twice.</em>
</p>

---

## 📂 Repository Layout
- `powershell/` → AD migration helpers, domain readiness checks, PDQ Deploy scripts  
- `bash/` → Pi-hole + Nginx Proxy Manager backups, TrueNAS automations, scheduled jobs  
- `python/` → Log analysis, Grafana data feeds, reporting tools  
- `aws/` → CloudFormation templates, connectivity test scripts, troubleshooting helpers  
- `misc/` → Anything that doesn’t fit neatly into a box (yet)  

---

## ⚡ Featured Scripts
- **🗂️ AD Domain Readiness Checker**  
  PowerShell script for verifying DCs, GPOs, replication, and DNS health before migrations.  

- **🛡️ Pi-hole Auto Backup to TrueNAS**  
  Bash script with rotation + restore logic, keeping network DNS configs safe.  

- **📊 Jellyfin Log → Grafana**  
  Promtail + Python helpers to visualize streaming errors in Grafana dashboards.  

- **☁️ AWS DC Connectivity Toolkit**  
  Quick scripts to test RPC/135 + high ports across on-prem ↔ AWS DCs.  

- **💰 Budget Tracker Automations**  
  Excel/Sheets scripts for rolling up petrol, groceries, and “pots” into clean dashboards.  

---

## 📊 Tech Stack in Action
This repo pulls from my wider environment:  

- **On-prem** → Windows Server 2016 → 2025 DC migrations, PDQ Deploy/Inventory  
- **Cloud** → AWS EC2 DCs, SG/NACL troubleshooting, CloudFormation infra  
- **Home-Lab** → TrueNAS SCALE (“tank” pool), Docker Compose stacks (Jellyfin, Sonarr, qBittorrent, Pi-hole)  
- **Monitoring** → Grafana + InfluxDB + Promtail log shipping  

---

## 📜 License
MIT License — free to use, adapt, and share.  

---

## 🤝 Contributions
Got an idea, optimization, or a script worth sharing? Open a PR or raise an issue.  
