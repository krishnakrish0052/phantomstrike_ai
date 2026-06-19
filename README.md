<div align="center">

<img src="assets/phantomstrike-logo.png" alt="PhantomStrike" width="220"/>

# PhantomStrike
*Previously: Hexstrike AI Community Edition*

### AI-powered offensive security orchestration engine

### ⚡ From target → recon → exploit chain in minutes

⭐ If PhantomStrike improves your workflow, consider starring the repo — it helps others discover it.

[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red.svg)](https://github.com/CommonHuman-Lab/phantomstrike)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://github.com/CommonHuman-Lab/phantomstrike)

</div>

## What is PhantomStrike?

PhantomStrike connects LLM agents to real offensive security tools and executes full attack chains — from recon to exploitation.

---

## 🚀 Quick Start (Installation)

> Get a full offensive security environment running in minutes.

```bash
git clone https://github.com/CommonHuman-Lab/phantomstrike.git
cd phantomstrike

./phantomstrike.sh -a               # Setup + start server
./phantomstrike.sh -a -ai           # + local AI model (~8.4 GB RAM)
./phantomstrike.sh -a -ai-small     # + smaller AI model (~2.5 GB RAM)

# Docker
docker compose up --build -d    # Build + start
docker compose down             # Stop

```

> Full flag reference: [Wiki — Installation & Flags](https://github.com/CommonHuman-Lab/phantomstrike/wiki/Installation-and-Flags)

### Verify Setup

Open [http://localhost:8888](http://localhost:8888) to access the dashboard.

> Some tools (e.g. `nmap`, `masscan`) require elevated privileges for specific scan modes. Use a dedicated test VM and least-privilege setup where possible.

---

## 🔌 AI Agent Integrations (MCP)

Connect PhantomStrike to any MCP-compatible AI client — OpenCode, Cursor, Claude Desktop, VS Code Copilot, Roo Code, and more.

### Universal MCP Command

```bash
/path/to/phantomstrike/phantomstrike-env/bin/python3 \
  /path/to/phantomstrike/phantomstrike_mcp.py \
  --server http://127.0.0.1:8888 \
  --profile full
```

### OpenCode

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "phantomstrike": {
      "type": "local",
      "command": [
        "/path/to/phantomstrike/phantomstrike-env/bin/python3",
        "/path/to/phantomstrike/phantomstrike_mcp.py",
        "--server",
        "http://127.0.0.1:8888",
        "--profile",
        "full"
      ],
      "enabled": true
    }
  }
}
```

> Config snippets for Claude Desktop, Cursor, VS Code Copilot, and security options: [Wiki — MCP Setup](https://github.com/CommonHuman-Lab/phantomstrike/wiki/MCP-Setup)

---

## 🔧 Features

PhantomStrike does not just run tools — it orchestrates full attack chains using AI decision-making.

- AI agents that chain tools automatically
- 185+ offensive security tools, all agent-controllable
- Full attack workflow: recon → enumeration → exploitation → reporting
- Modular tool registry — add or remove tools without touching agent logic
- MCP-compatible — plug into any AI client you already use
- Real-time session dashboard with live command output and logs

> [Full feature breakdown](https://github.com/CommonHuman-Lab/phantomstrike/wiki/Features) · [Session & workbench docs](https://github.com/CommonHuman-Lab/phantomstrike/wiki/Dashboard-and-Sessions)

---

## 🧰 Tool Arsenal

185+ offensive security tools across 12 categories — all dynamically orchestrated by AI agents in real time.

- Network reconnaissance
- Web exploitation
- Wireless security
- OSINT & intelligence gathering
- Password attacks
- Cloud & API security

> [Full tool list by category](https://github.com/CommonHuman-Lab/phantomstrike/wiki/Tool-Arsenal)

---

## ⚠️ Security Considerations

> PhantomStrike gives AI agents direct access to offensive security tooling.

- Run only in isolated environments or dedicated security testing VMs  
- AI agents may execute real commands — maintain operator oversight  
- Monitor activity via dashboard and logs in real time  
- Use `PHANTOMSTRIKE_API_TOKEN` for any non-local deployment

### Legal & Ethical Use

| Allowed | Not Allowed |
|---|---|
| Authorized penetration testing (with written authorization) | Unauthorized testing of any system |
| Bug bounty programs (within program scope and rules) | Malicious, illegal, or harmful activities |
| CTF competitions and educational environments | Unauthorized data access or exfiltration |
| Security research on owned or authorized systems | |
| Red team exercises (with organizational approval) | |

---

## 📜 License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.

---

## ⭐ Support the project

If PhantomStrike is useful to your workflow:

- Star the repository
- Share it with others
- Contribute improvements

It makes a real difference.

---

## Credits

Originally inspired by [hexstrike-ai](https://github.com/0x4m4/hexstrike-ai).
