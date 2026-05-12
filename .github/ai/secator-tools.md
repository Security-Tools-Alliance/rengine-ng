# Secator — Supported Tools

List of tools integrated in [Secator](https://github.com/freelabz/secator). reNgine-ng runs scans via Secator; workflows and tasks are defined in the Secator config and can be listed with `get_configs_by_type("workflow")`, `get_configs_by_type("scan")`, `get_configs_by_type("task")`.

**Documentation:** [Secator docs (GitHub)](https://github.com/freelabz/secator-docs) · [Secator (main repo)](https://github.com/freelabz/secator)

---

## Reconnaissance

### recon/dns

| Tool | Description | Link |
|------|-------------|------|
| **dnsx** | Fast multi-purpose DNS toolkit (queries). | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |
| **dnsxbrute** | Same as dnsx, bruteforce mode. | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |
| **subfinder** | Fast subdomain finder. | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |

### recon/ip

| Tool | Description | Link |
|------|-------------|------|
| **fping** | Find alive hosts on local networks. | [fping.org](https://fping.org/) |
| **mapcidr** | Expand CIDR ranges into IPs. | [projectdiscovery/mapcidr](https://github.com/projectdiscovery/mapcidr) |

### recon/port

| Tool | Description | Link |
|------|-------------|------|
| **naabu** | Fast port discovery tool. | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) |

### recon/user

| Tool | Description | Link |
|------|-------------|------|
| **maigret** | Hunt for user accounts across many websites. | [soxoj/maigret](https://github.com/soxoj/maigret) |

---

## HTTP & crawling

### http

| Tool | Description | Link |
|------|-------------|------|
| **httpx** | Fast HTTP prober. | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |

### http/crawler

| Tool | Description | Link |
|------|-------------|------|
| **cariddi** | Fast crawler, endpoint secrets / API keys / tokens matcher. | [edoardottt/cariddi](https://github.com/edoardottt/cariddi) |
| **gau** | Offline URL crawler (Alien Vault, Wayback Machine, Common Crawl, URLScan). | [lc/gau](https://github.com/lc/gau) |
| **gospider** | Fast web spider (Go). | [jaeles-project/gospider](https://github.com/jaeles-project/gospider) |
| **katana** | Next-generation crawling and spidering framework. | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) |

### http/fuzzer

| Tool | Description | Link |
|------|-------------|------|
| **dirsearch** | Web path discovery. | [maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) |
| **feroxbuster** | Fast recursive content discovery (Rust). | [epi052/feroxbuster](https://github.com/epi052/feroxbuster) |
| **ffuf** | Fast web fuzzer (Go). | [ffuf/ffuf](https://github.com/ffuf/ffuf) |

---

## OSINT

| Tool | Description | Link |
|------|-------------|------|
| **h8mail** | Email OSINT and breach hunting. | [khast3x/h8mail](https://github.com/khast3x/h8mail) |

---

## Vulnerability scanning

### vuln/code

| Tool | Description | Link |
|------|-------------|------|
| **grype** | Vulnerability scanner for container images and filesystems. | [anchore/grype](https://github.com/anchore/grype) |

### vuln/http

| Tool | Description | Link |
|------|-------------|------|
| **dalfox** | XSS scanning and parameter analysis. | [hahwul/dalfox](https://github.com/hahwul/dalfox) |
| **msfconsole** | Metasploit Framework CLI. | [Metasploit overview](https://docs.rapid7.com/metasploit/msf-overview) |

### vuln/multi

| Tool | Description | Link |
|------|-------------|------|
| **wpscan** | WordPress security scanner. | [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) |
| **nmap** | Port/vuln scanning with NSE scripts. | [nmap/nmap](https://github.com/nmap/nmap) |
| **nuclei** | Fast configurable vuln scanner (YAML DSL). | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |

---

## Other

### tagger

| Tool | Description | Link |
|------|-------------|------|
| **gf** | Wrapper around grep for common patterns. | [tomnomnom/gf](https://github.com/tomnomnom/gf) |

---

*Source: [secator-docs README](https://github.com/freelabz/secator-docs). Tool list may evolve; check the repo for the latest.*
