# Changelog

All notable user-friendly changes to reNgine-ng will be documented in this file.

For technical details about each release, see [the GitHub releases page](https://github.com/Security-Tools-Alliance/rengine-ng/releases).

## [2.2.0] - 11-08-2025

### 🆕 Major New Features

#### LLM Integration & AI-Powered Analysis

- Full LLM Support: Complete integration supporting both OpenAI and Ollama models
- Ollama Model Management: Real-time model download, selection, listing, and deletion with WebSocket progress tracking
- AI Attack Surface Analysis: LLM-powered attack surface suggestions and vulnerability reporting
- Unified Model Manager: Replace GPT-specific workflows with unified LLM architecture

#### GPU Acceleration Support

- NVIDIA GPU Support: Native CUDA acceleration for LLM processing
- AMD GPU Compatibility: ROCm support for AMD graphics cards
- Performance Optimization: GPU-accelerated model inference and processing

#### Enhanced Scanning Engine

- Nmap Integration: Advanced port/service discovery using Nmap
- Improved Endpoint Detection: Better first endpoint detection for IP addresses
- Enhanced Result Parsing: Support for ports, services, and vulnerability modes
- Robust Path Handling: Secure file operations and path management

### 🔧 Infrastructure & DevOps Improvements

#### Docker & Build System

- Multi-architecture Support: ARM64 and AMD64 Docker images
- Build Optimization: Updated Docker build workflows and metadata handling
- CI/CD Enhancements: Improved GitHub Actions with better tagging strategies
- Container Improvements: Enhanced Gunicorn server configuration and entrypoint scripts

#### Installation & Updates

- Installation Script: Improved installation process with update checking
- Version Management: Better version detection and upgrade workflows
- Testing Framework: Expanded test coverage with role-based access controls

### 🎨 Frontend & UI Enhancements

#### LLM Toolkit Interface

- Model Management UI: Interactive model download/deletion interface
- Real-time Progress: WebSocket-powered download progress indicators
- Modern Interface: Streamlined model selection and result rendering
- Content Sanitization: Safe HTML rendering for LLM-generated content

#### Dashboard Improvements

- Enhanced Analytics: Better vulnerability and scan result visualization
- Role-based Access: Improved permissions and user management
- Markdown Support: Rich text rendering for reports and documentation

### 🛠️ Technical Improvements

#### Backend Refactoring

- Code Organization: Restructured scan tasks and utilities
- Enhanced Logging: Improved error tracking and vulnerability logging
- Task Management: Better Celery task handling and retry mechanisms
- WebSocket Integration: Real-time communication for model operations

#### Security & Validation

- Input Sanitization: Enhanced data validation and security measures
- Path Security: Safe file operations and directory handling
- Authentication: Improved user management and permissions

### 🐛 Bug Fixes & Stability

- Duplicate Port Resolution: Fixed duplicate port detection issues
- IP Endpoint Detection: Improved first endpoint detection for IP addresses
- Dependency Management: Updated tool configurations and directory structures
- Configuration Fixes: Resolved various configuration file path issues
- Test Stability: Enhanced test coverage and reliability

## [2.1.0] - 2024-11-06

### Added (2.1.0)

• feat(release): update release/2.1.0 from upstream by @psyray in #86
• feat(ui): mask API keys in settings view by @yarysp in #80
• feat(install): arm64 support by @yarysp in #82
• ops(install): use python venv (pipx/poetry) to fix/prevent conflicting packages by @psyray & @Talanor in #84
• build(install): migrate to GitHub Container Registry, optimize Docker setup, and update install scripts by @psyray & @Talanor in #139
• build(ci): build Docker image and upload to GitHub container registry by @AnonymousWP in #138
• build(docker): add ARM support for Celery Dockerfile by @psyray in #161
• build(docker): improve makefile, docker verbosity & provide unit tests by @psyray in #155
• dev(django): install django extensions to have more commands by @psyray in #196
• feat(ui): disable update button in tool arsenal by @psyray in #200
• feat(todo): enhance todo functionality and error handling by @psyray in #198
• project(ui): confine users to projects and standardize slug usage by @psyray in #154
• feat(ui): bulk remove vulnerabilities by @0b3ud in #168
• feat: reintroduce Lark notification fields in scanEngine by @psyray in #207
• feat: enhance IP retrieval with caching by @psyray in #215
• build(docker): refactor detection of OS and add support for RHEL distros by @AnonymousWP in #211
• Release/2.1.0 by @AnonymousWP in #1

### Fixed (2.1.0)

• fix(docs): change art logo and fix doc link by @psyray in #137
• fix(cidr): add CIDR import by @pbehnke in #141
• fix(ui): restore static files path & remove beat entrypoint useless code by @psyray in #145
• fix(conflicts): fix merge conflicts for branch release/2.1.0 by @psyray in #150
• fix(scan): subdomain import with suffix more than 4 chars by @yogeshojha in #147
• build(ci): extract issue number from PR body by @AnonymousWP in #153
• docs(readme): set badge to latest release automatically by @psyray in #158
• docs(readme): remove space after url by @psyray in #159
• fix(ui): permit to link tab URL and history back into it by @yogeshojha in #164
• fix(celery): wafw00f install by @psyray in #166
• fix(ui): load default yaml config on add scan engine form by @psyray in #171
• fix(ui): tools settings page by @psyray in #169
• fix(oneforall): wrong s3 bucket reported by @Talanor in #176
• fix(ssl): add SAN extension to the cert by @michschl in #178
• fix(ui): stored XSS by @yogeshojha in #180
• fix(install): revert changes of prebuilt chain by @psyray in #183
• fix(ui): fix 500 error on scan engine add by @psyray in #184
• build(install): improve root detection and set ownership on files by @psyray in #186
• fix(scan): fix clocked and scheduled scan not working by @yogeshojha in #182
• fix(graph): de-duplicate dorks and vulnerabilities by @psyray in #188
• build(docker): replace staticfiles volume to prevent empty directory by @psyray in #199
• fix(custom_header): not correctly parsing parameters by @psyray in #172
• fix: change install_type value in .env-dist and add missing imports by @psyray in #201
• refactor: replace hardcoded API URLs with dynamic endpoint URLs by @psyray in #206
• refactor: update modal handling and improve CMS detection by @psyray in #210
• refactor: update delete functions to use URL endpoints by @psyray in #213
• refactor: update URL handling by @psyray in #214
• fix: apply github-advanced-security recommendations by @psyray in #220

### Miscellaneous (2.1.0)

• chore(deps): bump requests from 2.31.0 to 2.32.2 in /web by @dependabot in #105
• chore(deps): bump django from 3.2.4 to 3.2.25 in /web by @dependabot in #104
• build(ci): add CI for closing issues when PR is merged by @AnonymousWP in #144
• build(ci): add write permissions by @AnonymousWP in #163
• docs(readme): remove note by @AnonymousWP in #167
• docs(readme): redirect install & update section to the wiki pages by @psyray in #185
• build(ci): build docker images for each tag, release, push by @psyray in #151
• build(images): restrict image creation, add correct tags and clean non tagged images by @psyray in #193
• build(ci): improve CodeQL configuration by @AnonymousWP in #194
• ci(unit-tests): provide unit tests for UI by @psyray in #189
• refactor: improve robustness of nuclei result parsing by @psyray in #209
• refactor: update wordlists and configuration defaults by @psyray in #221

### New Contributors (2.1.0)

• @dependabot made their first contribution in #105
• @0b3ud made their first contribution in #168
• @pbehnke made their first contribution in #141
• @Talanor made their first contribution in #176
• @michschl made their first contribution in #178

Full Changelog: <https://github.com/Security-Tools-Alliance/rengine-ng/compare/v2.0.7...v2.1.0>

## [2.0.7] - 2024-08-14

### Added (2.0.7)

• dev(debug): complete dev environment to debug/code easily by @yarysp in #68
• build(ci): automate releases based on tags and labels by @AnonymousWP in #111
• build(install/uninstall/update): improve usability, readability and overall user experience of output by @AnonymousWP in #95
• feat(version): centralize version management in web/reNgine/version.txt by @psyray in #131
• feat(docker): add support for old docker-compose command by @psyray in #132

### Fixed (2.0.7)

• fix(security): OS Command Injection vulnerability (x2) by @AnonymousWP in #2
• feat: update to 2.0.6 from upstream by @yarysp in #79
• ops(install): fix rengine install/uninstall by @yarysp in #81
• fix(file_fuzz): subdomain_id key error by @psyray in #88
• refactor(scan): custom headers by @psyray in #90
• fix(security): rework scan working folder location to prevent leaks by @psyray in #92
• fix(scan): fix bad base path retrieval for results dir by @psyray in #94
• fix(scan): rework the alive endpoint and redirection operation by @psyray in #96
• fix(scan): check value returned for all subs saved by @psyray in #100
• fix(scan): rework http_crawl to update subdomain datas by @psyray in #102
• fix(ui): reset osint dork result id before display by @psyray in #103
• fix(scan): centralize and log subdomains creation by @psyray in #97
• fix(tools): update git tools at startup by @psyray in #98
• fix(scan): add some iterable checks to prevent TypeError by @psyray in #113
• fix(screenshot): get only some columns from csv file by @psyray in #114
• fix(ui): escape vulnerability request/response in db and display in ui by @psyray in #118
• fix(fetch_url): fix unwanted subdomain and rework fetch_url task by @psyray in #126
• build(ci): fix missing write permissions by @AnonymousWP in #135

### Miscellaneous

• chore(issue-templates): refactor issue forms by @AnonymousWP in #61
• docs(readme): fix links and images by @psyray in #65
• docs: update expired Discord invitation link with non expiring one by @psyray in #109
• docs: refactor documentation by @AnonymousWP in #115
• build(deps): bump Django deps to fix security issues by @psyray in #133

### New Contributors (2.0.7)

• @AnonymousWP made their first contribution in #2

Full Changelog: <https://github.com/Security-Tools-Alliance/rengine-ng/compare/v2.0.3...v2.0.7>

## 2.0.6

**Release Date: May 11, 2024**

### What's Changed (2.0.6)

- Fix installation error and celery workers having issues with httpcore
- remove duplicate gospider references by @Talanor in <https://github.com/yogeshojha/rengine/pull/1245>
- Fix "subdomain" s3 bucket by @Talanor in <https://github.com/yogeshojha/rengine/pull/1244>
- Fix Txt File Var Declaration by @specters312 in <https://github.com/yogeshojha/rengine/pull/1239>
- Bug Correction: When dumping and loading customscanengines by @TH3xACE in <https://github.com/yogeshojha/rengine/pull/1224>
- Fix/infoga removal by @yogeshojha in <https://github.com/yogeshojha/rengine/pull/1249>
- Fix #1241 by @yogeshojha in <https://github.com/yogeshojha/rengine/pull/1251>

### New Contributors (2.0.6)

- @Talanor made their first contribution in <https://github.com/yogeshojha/rengine/pull/1245>

- @specters312 made their first contribution in <https://github.com/yogeshojha/rengine/pull/1239>
- @TH3xACE made their first contribution in <https://github.com/yogeshojha/rengine/pull/1224>

**Full Changelog**: <https://github.com/yogeshojha/rengine/compare/v2.0.5...v2.0.6>

## 2.0.5

**Release Date: April 20, 2024**

- Fix #1234 reNgine unable to load celery tasks due to mismatched celery and redis versions

## 2.0.4

**Release Date: April 18, 2024**

### What's Changed (2.0.4)

- chore: update version number to 2.0.3 by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1180>

- Fix various ffuf bugs by @yarysp in <https://github.com/yogeshojha/rengine/pull/1199>
- Set and update default YAML config with all latest vars by @yarysp in <https://github.com/yogeshojha/rengine/pull/1200>
- Add checks for placeholder in custom tool task by @yarysp in <https://github.com/yogeshojha/rengine/pull/1201>
- Whatportis - Replace purge by truncate to prevent port import error by @yarysp in <https://github.com/yogeshojha/rengine/pull/1203>
- ops(installation): fix nano not being installed when absent by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1143>
- Complete dev environment to debug/code easily by @yarysp in <https://github.com/yogeshojha/rengine/pull/1196>
- Revert "Complete dev environment to debug/code easily" by @yogeshojha in <https://github.com/yogeshojha/rengine/pull/1225>
- Update README.md | Fixed 1 broken link to the regine.wiki by @jostasik in <https://github.com/yogeshojha/rengine/pull/1226>
- Fix uninitialised variable cmd in custom_subdomain_tools by @cpandya2909 in <https://github.com/yogeshojha/rengine/pull/1207>
- [FIX] security: OS Command Injection vulnerability (x2) #1219 by @0xtejas in <https://github.com/yogeshojha/rengine/pull/1227>

## New Contributors :rocket:

- @yarysp made their first contribution in <https://github.com/yogeshojha/rengine/pull/1199>

- @jostasik made their first contribution in <https://github.com/yogeshojha/rengine/pull/1226>
- @cpandya2909 made their first contribution in <https://github.com/yogeshojha/rengine/pull/1207>
- @0xtejas made their first contribution in <https://github.com/yogeshojha/rengine/pull/1227>

**Full Changelog**: <https://github.com/yogeshojha/rengine/compare/v2.0.3...v2.0.4>

## 2.0.3

**Release Date: January 25, 2024**

### What's Changed (2.0.3)

- CI: update GitHub action versions by @jxdv in <https://github.com/yogeshojha/rengine/pull/1136>

- Fixed (subdomain_discovery | ERROR | local variable 'use_amass_config' referenced before assignment) by @Deathpoolxrs in <https://github.com/yogeshojha/rengine/pull/1149>
- chore: update LICENSE by @jxdv in <https://github.com/yogeshojha/rengine/pull/1153>
- Fix subdomains list empty in Target by @psyray in <https://github.com/yogeshojha/rengine/pull/1166>
- Fix top menu text overflow in low resolution by @psyray in <https://github.com/yogeshojha/rengine/pull/1167>
- Update auto comment workflow due to deprecation warnings by @ErdemOzgen in <https://github.com/yogeshojha/rengine/pull/1126>
- Change Redirect URL after login to prevent 500 error by @psyray in <https://github.com/yogeshojha/rengine/pull/1124>
- fix-1030: Add missing slug on target summary link by @psyray in <https://github.com/yogeshojha/rengine/pull/1123>

### New Contributors (2.0.3)

- @Deathpoolxrs made their first contribution in <https://github.com/yogeshojha/rengine/pull/1149>

- @ErdemOzgen made their first contribution in <https://github.com/yogeshojha/rengine/pull/1126>

**Full Changelog**: <https://github.com/yogeshojha/rengine/compare/v2.0.2...v2.0.3>

## 2.0.2

**Release Date: December 8, 2023**

### What's Changed (2.0.2)

- Added tooltip text to dashboard total vulnerabilities tooltip by @luizmlo in <https://github.com/yogeshojha/rengine/pull/1029>

- ops(`uninstall.sh`): add missing volumes and echo messages by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/977>
- Fix no results in target subdomain list by @psyray in <https://github.com/yogeshojha/rengine/pull/1036>
- Fix Tool Settings Broken Link by @aqhmal in <https://github.com/yogeshojha/rengine/pull/1021>
- Fix subdomains list empty in Target by @psyray in <https://github.com/yogeshojha/rengine/pull/1053>
- Raise page limit to 500 for popup list by @psyray in <https://github.com/yogeshojha/rengine/pull/1051>
- Add directories count on Directories list by @psyray in <https://github.com/yogeshojha/rengine/pull/1050>
- ops(docker-compose): upgrade to 2.23.0 by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1023>
- Fix endpoints list and count by @psyray in <https://github.com/yogeshojha/rengine/pull/1041>
- Fix failing visualization when dorks are present by @psyray in <https://github.com/yogeshojha/rengine/pull/1045>
- Fix note not saving by @psyray in <https://github.com/yogeshojha/rengine/pull/1047>
- Count only not done todos in subdomains list by @psyray in <https://github.com/yogeshojha/rengine/pull/1048>
- Fix user agent definition keyword by @psyray in <https://github.com/yogeshojha/rengine/pull/1054>
- Upgrade project discovery tool at CT build by @psyray in <https://github.com/yogeshojha/rengine/pull/1055>
- Add a check to not load datatables twice by @psyray in <https://github.com/yogeshojha/rengine/pull/1039>
- Nmap port scan fails when Naabu return no port by @psyray in <https://github.com/yogeshojha/rengine/pull/1067>
- chore(issue-templates): incorrect label name by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1066>
- Endpoints list popup empty by @psyray in <https://github.com/yogeshojha/rengine/pull/1070>
- Add missing domain id value in subscan by @psyray in <https://github.com/yogeshojha/rengine/pull/1069>
- Fixes for #1033, #1026, #1027 by @yogeshojha in <https://github.com/yogeshojha/rengine/pull/1071>
- Temporary fix to prevent celery beat crash by @psyray in <https://github.com/yogeshojha/rengine/pull/1072>
- fix: ffuf ANSI code processing preventing task to finish by @ocervell in <https://github.com/yogeshojha/rengine/pull/1058>
- Update views.py by @Vijayragha1 in <https://github.com/yogeshojha/rengine/pull/1074>
- Fix crash on saving endpoint (FFUF related only) by @psyray in <https://github.com/yogeshojha/rengine/pull/1063>
- chore(issue-templates): fix incorrect description by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1078>
- IOError -> OSError by @jxdv in <https://github.com/yogeshojha/rengine/pull/1081>
- Add directories count on Directories list by @psyray in <https://github.com/yogeshojha/rengine/pull/1090>
- chore(issue-template): don't allow blank issues by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1089>
- Fix bad nuclei config name by @psyray in <https://github.com/yogeshojha/rengine/pull/1098>
- disallow empty password by @yogeshojha in <https://github.com/yogeshojha/rengine/pull/1105>
- fix attribute error on scan history #1103 by @yogeshojha in <https://github.com/yogeshojha/rengine/pull/1104>
- issue-633: added already-in-org filter to target dropdown in org form by @SeanOverton in <https://github.com/yogeshojha/rengine/pull/1106>
- Update Dockerfile to fix silicon incompatability by @SubGlitch1 in <https://github.com/yogeshojha/rengine/pull/1107>
- Add source for nmap scan by @psyray in <https://github.com/yogeshojha/rengine/pull/1108>
- Spelling mistake in hackerone.html by @Linuxinet in <https://github.com/yogeshojha/rengine/pull/1112>
- fix(version): incorrect number in art by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1111>
- Fix report generation when `Ignore Informational Vulnerabilities` checked by @psyray in <https://github.com/yogeshojha/rengine/pull/1100>
- fix(tool_arsenal): incorrect regex version numbers by @AnonymousWP in <https://github.com/yogeshojha/rengine/pull/1086>

### New Contributors (2.0.2)

- @luizmlo made their first contribution in <https://github.com/yogeshojha/rengine/pull/1029> :partying_face:

- @aqhmal made their first contribution in <https://github.com/yogeshojha/rengine/pull/1021> :partying_face:
- @C0wnuts made their first contribution in <https://github.com/yogeshojha/rengine/pull/973> :partying_face:
- @ocervell made their first contribution in <https://github.com/yogeshojha/rengine/pull/1058> :partying_face:
- @Vijayragha1 made their first contribution in <https://github.com/yogeshojha/rengine/pull/1074> :partying_face:
- @jxdv made their first contribution in <https://github.com/yogeshojha/rengine/pull/1081> :partying_face:
- @SeanOverton made their first contribution in <https://github.com/yogeshojha/rengine/pull/1106> :partying_face:
- @SubGlitch1 made their first contribution in <https://github.com/yogeshojha/rengine/pull/1107> :partying_face:
- @Linuxinet made their first contribution in <https://github.com/yogeshojha/rengine/pull/1112> :partying_face:

**Full Changelog**: <https://github.com/yogeshojha/rengine/compare/v2.0.1...v2.0.2>

Once again excellent work on reNgine v2.0.2 by @AnonymousWP, @psyray, @ocervell and everybody else! :rocket:

## 2.0.1

**Release Date: October 24, 2023**

2.0.1 fixes a ton of issues in reNgine 2.0.

Fixes:

1. Prevent duplicating Nuclei vulns for subdomain #1012 @psyray
2. Fixes for empty subdomain returned during nuclei scan #1011 @psyray
3. Add all the missing slug in scanEngine view & other places #1005 @psyray
4. Foxes for missing vulscan script #1004 @psyray
5. Fixes for missing slug in report settings saving #1003
6. Fixes for Nmap Parsing Error #1001 #1002 @psyray
7. Fix nmap script ports iterable args #1000 @psyray
8. Iterate over hostnames when multiple #1002 @psyray
9. Gau install #998, change gauplus to gau @psyray
10. Add missing slug parameter in schedule scan #996 @psyray
11. Add missing slug parameter in schedule scan #996, fixes #940, #937, #897, #764 @psyray
12. Add stack trace into make logs if DEBUG True #994 @psyray
13. Fix dirfuzz base64 name display #993 #992 @psyray
14. Fix target subdomains list not loading #991 @psyray
15. Change WORDLIST constant value #987, fixes #986@psyray
16. fix(notification_settings): submitting results in error 502 #981 fixes #970 @psyray
17. Fixes with documentation and installation/update/uninstall scripts @anonymousWP
18. Fix file directory popup not showing in detailed scan #912 @psyray

@AnonymousWP and @psyray have been phenomenal in fixing these bugs. Thanks to both of you! :heart: :rocket:

## 2.0.0

**Release Date: October 7, 2023**

### Added

- Projects: Projects allow you to efficiently organize their web application reconnaissance efforts. With this feature, you can create distinct project spaces, each tailored to a specific purpose, such as personal bug bounty hunting, client engagements, or any other specialized recon task.
- Roles and Permissions: assign distinct roles to your team members: Sys Admin, Penetration Tester, and Auditor—each with precisely defined permissions to tailor their access and actions within the reNgine ecosystem.
- GPT-powered Report Generation: With the power of OpenAI's GPT, reNgine now provides you with detailed vulnerability descriptions, remediation strategies, and impact assessments.
- API Vault: This feature allows you to organize your API keys such as OpenAI or Netlas API keys.
- GPT-powered Attack Surface Generation
- - URL gathering now is much more efficient, removing duplicate endpoints based on similar HTTP Responses, having the same content_length, or page_title. Custom duplicate fields can also be set from the scan engine configuration.
- URL Path filtering while initiating scan: For instance, if we want to scan only endpoints starting with <https://example.com/start/>, we can pass the /start as a path filter while starting the scan. [@ocervell](https://github.com/ocervell)
+- Expanding Target Concept: reNgine 2.0 now accepts IPs, URLs, etc as targets. (#678, #658) Excellent work by [@ocervell](https://github.com/ocervell)
- A ton of refactoring on reNgine's core to improve scan efficiency. Massive kudos to [@ocervell](https://github.com/ocervell)
- Created a custom celery workflow to be able to run several tasks in parallel that are not dependent on each other, such OSINT task and subdomain discovery will run in parallel, and directory and file fuzzing, vulnerability scan, screenshot gathering etc. will run in parallel after port scan or url fetching is completed. This will increase the efficiency of scans and instead of having one long flow of tasks, they can run independently on their own. [@ocervell](https://github.com/ocervell)
- Refactored all tasks to run asynchronously [@ocervell](https://github.com/ocervell)
- Added a stream_command that allows to read the output of a command live: this means the UI is updated with results while the command runs and does not have to wait until the task completes. Excellent work by [@ocervell](https://github.com/ocervell)
- Pwndb is now replaced by h8mail. [@ocervell](https://github.com/ocervell)
- - Group Scan Results: reNgine 2.0 allows grouping of subdomains based on similar page titles and HTTP status, and also vulnerability grouping based on the same vulnerability title and severity.
- Added Support for Nmap: reNgine 2.0 allows to run Nmap scripts and vuln scans on ports found by Naabu. [@ocervell](https://github.com/ocervell)
- Added support for Shared Scan Variables in Scan Engine Configuration:
  - `enable_http_crawl`: (true/false) You can disable it to be more stealthy or focus on something different than HTTP
  - `timeout`: set timeout for all tasks
  - `rate_limit`: set rate limit for all tasks
  - `retries`: set retries for all tasks
  - `custom_header`: set the custom header for all tasks
- Added Dalfox for XSS Vulnerability Scan
- Added CRLFuzz for CRLF Vulnerability Scan
- Added S3Scanner for scanning misconfigured S3 buckets
- Improve OSINT Dork results, now detects admin panels, login pages and dashboards
- Added Custom Dorks
- Improved UI for vulnerability results, clicking on each vulnerability will open up a sidebar with vulnerability details.
- Added HTTP Request and Response in vulnerability Results
- Under Admin Settings, added an option to allow add/remove/deactivate additional users
- Added Option to Preview Scan Report instead of forcing to download
- Added Katana for crawling and spidering URLs
- Added Netlas for Whois and subdomain gathering
- Added TLSX for subdomain gathering
- Added CTFR for subdomain gathering
- Added historical IP in whois section
- Added Pagination on Large datatables such as subdomains, endpoints, vulnerabilities etc #949 [@psyray](https://github.com/psyray)

### Fixes

- GF patterns do not run on 404 endpoints (#574 closed)
- Fixes for retrieving whois data (#693 closed)
- Related/Associated Domains in Whois section is now fixed
- Fixed missing lightbox css & js on target screenshot page #947 #948 [@psyray](https://github.com/psyray)
- Issue in Port-scan: int object is not subscriptable Fixed #939, #938 [@AnonymousWP](https://github.com/AnonymousWP)

### Removed

- Removed pwndb and tor related to it.
- Removed tor for pwndb

## 1.3.6

**Release Date: March 2, 2023**

- Fixed installation errors. Fixed #824, #823, #816, #809, #803, #801, #798, #797, #794, #791 .

## 1.3.5

**Release Date: December 29, 2022**

- Fixed #769, #768, #766, #761, Thanks to, @bin-maker, @carsonchan12345, @paweloque, @opabravo

## 1.3.4

**Release Date: November 16, 2022**

### Fixes (1.3.4)

- Fixed #748 , #743 , #738, #739

## 1.3.3

**Release Date: October 9, 2022**

### Fixes (1.3.3)

- #723, Upgraded Go to 1.18.2

## 1.3.2

**Release Date: August 20, 2022**

### Fixes (1.3.2)

- #683 For Filtering GF tags
- #669 Where Directory UI had to be collapsed

## 1.3.1

**Release Date: August 12, 2022**

### Fixes (1.3.1)

- Fix for #643 Downloading issue for Subdomain and Endpoints
- Fix for #627 Too many Targets causes issues while loading datatable
- Fix version Numbering issue

## 1.3.0

**Release Date: July 11, 2022**

### Added (1.3.0)

- Geographic Distribution of Assets Map
- Added WAF Detector as an optional tool in Scan Engine

### Fixes (1.3.0)

- WHOIS Provider Changed
- Fixed Dark UI Issues
- Fix HTTPX Issue with custom Header

## 1.2.0

**Release Date: May 27, 2022**

### Added (1.2.0)

- Naabu Exclude CDN Port Scanning
- Added WAF Detection

### Fixes (1.2.0)

- Fix #630 Character Name too Long Issue
- [Security] Fixed several instances of Command Injections, CVE-2022-28995, CVE-2022-1813
- Hakrawler Fixed - #623
- Fixed XSS on Hackerone report via Markdown
- Fixed XSS on Import Target using malicious filename
- Stop Scan Fixed #561
- Fix installation issue due to missing curl
- Updated docker-compose version

## 🏷️ 1.1.0

**Release Date: Apr 24, 2022**

- Redesigned UI
- Added Subscan Feature

    Subscan allows further scanning any subdomains. Assume from a normal recon process you identified a subdomain that you wish to do port scan. Earlier, you had to add that subdomain as a target. Now you can just select the subdomain and initiate subscan.

- Ability to Download reconnaissance or vulnerability report
- Added option to customize report, customization includes the look and feel of report, executive summary etc.

- Add IP Address from IP
- WHOIS Addition on Detail Scan and fetch whois automatically on Adding Single Targets
- Universal Search Box
- Addition of Quick Add menus
- Added ToolBox Feature

    ToolBox will feature most commonly used recon tools. One can use these tools to identify whois, CMSDetection etc without adding targets. Currently, Whois, CMSDetector and CVE ID lookup is supported. More tools to follow up.

- Notify New Releases on reNgine if available
- Tools Arsenal Section to feature preinstalled and custom tools
- Ability to Update preinstalled tools from Tools Arsenal Section
- Ability to download/add custom tools
- Added option for Custom Header on Scan Engine
- Added CVE_ID, CWE_ID, CVSS Score, CVSS Metrics on Vulnerability Section, this also includes lookup using cve_id, cwe_id, cvss_score etc
- Added curl command and references on Vulnerability Section
- Added Columns Filtering Option on Subdomain, Vulnerability and Endpoints Tables
- Added Error Handling for Failed Scans, reason for failure scan will be displayed
- Added Related Domains using WHOIS
- Added Related TLDs
- Added HTTP Status Breakdown Widget
- Added CMS Detector
- Updated Visualization
- Option to Download Selected Subdomains
- Added additional Nuclei Templates from <https://github.com/geeknik/the-nuclei-templates>
- Added SSRF check from Nagli Nuclei Template
- Added option to fetch CVE_ID details
- Added option to Delete Multiple Scans
- Added ffuf as Directory and Files fuzzer
- Added widgets such as Most vulnerable Targets, Most Common Vulnerabilities, Most Common CVE IDs, Most Common CWE IDs, Most Common Vulnerability Tags

And more...

## 🏷️ 1.0.1

**Release Date: Aug 29, 2021**

### Changelog (1.0.1)

- Fixed [#482](https://github.com/yogeshojha/rengine/issues/482) Endpoints and Vulnerability Datatable were showing results of other targets due to the scan_id parameter
- Fixed [#479](https://github.com/yogeshojha/rengine/issues/479) where the scan was failing due to recent httpx release, change was in the JSON output
- Fixed [#476](https://github.com/yogeshojha/rengine/issues/476) where users were unable to click on Clocked Scan (Reported only on Firefox)
- Fixed [#442](https://github.com/yogeshojha/rengine/issues/442) where an extra slash was added in Directory URLs
- Fixed [#337](https://github.com/yogeshojha/rengine/issues/337) where users were unable to link custom wordlist
- Fixed [#436](https://github.com/yogeshojha/rengine/issues/436) Checkbox in Notification Settings were not working due to same name attribute, now fixed
- Fixed [#439](https://github.com/yogeshojha/rengine/issues/439) Hakrawler crashed if the deep mode was activated due to -plain flag
- Fixed [#437](https://github.com/yogeshojha/rengine/issues/437) If Out of Scope subdomains were supplied, the scan was failing due to None value
- Fixed [#424](https://github.com/yogeshojha/rengine/issues/424) Multiple Targets couldn't be scanned

### Improvements (1.0.1)

- Enhanced install script, check for if docker is running service or not #468

### Security (1.0.1)

- Fixed Cross Site Scripting
  - [#460](https://github.com/yogeshojha/rengine/issues/460)
  - [#457](https://github.com/yogeshojha/rengine/issues/457)
  - [#454](https://github.com/yogeshojha/rengine/issues/454)
  - [#453](https://github.com/yogeshojha/rengine/issues/453)
  - [#459](https://github.com/yogeshojha/rengine/issues/459)
  - [#460](https://github.com/yogeshojha/rengine/issues/460)
- Fixed Cross Site Scripting reported on Huntr [#478](https://github.com/yogeshojha/rengine/issues/478)
    [https://www.huntr.dev/bounties/ac07ae2a-1335-4dca-8d55-64adf720bafb/](https://www.huntr.dev/bounties/ac07ae2a-1335-4dca-8d55-64adf720bafb/)

### Version 1.0 Major release

### Additions

- Dark Mode
- Recon Data visualization
- Improved correlation among recon data
- Ability to identify Interesting Subdomains
- Ability to Automatically report Vulnerabilities to Hackerone with customizable vulnerability report
- Added option to download URLs and Endpoints along with matched GF patterns
- Dorking support for stackoverflow, 3rdparty, social_media, project_management, code_sharing, config_files, jenkins, wordpress_files, cloud_buckets, php_error, exposed_documents, struts_rce, db_files, traefik, git_exposed
- Emails, metainfo, employees, leaked password discovery
- Optin to Add bulk targets
- Proxy Support
- Target Summary
- Recon Todo
- Unusual Port Identification
- GF patterns support #110, #88
- Screenshot Gallery with Filters
- Powerful recon data filtering with auto suggestions
- Added whatportis, this allows ports to be displayed as Service Name and Description
- Recon Data changes, finds new/removed subdomains/endpoints
- Tagging of targets into Organization
- Added option to delete all scan results or delete all screenshots inside Settings and reNgine settings
- Support for custom GF patterns and Nuclei Templates
- Support for editing tool related configuration files (Nuclei, Subfinder, Naabu, amass)
- Option to Mark Subdomains as important
- Separate tab for Directory scan results
- Option to Import Subdomains
- Clean your scan results and screenshots
- Enhanced and Customizable Scan alert with support for sending recon data directly to Discord
- Improvement in Vulnerability Scanning, If endpoint scan is performed, those endpoints will be an input to Nuclei.
- Ignore file extensions in URLs
- Added response time in endpoints and subdomains
- Added badge to identify CDN and non CDN IPs
- Added gospider, gauplus and waybackurls for url discovery
- Added activity log in Scan activity
- For better UX shifted nav bar from vertical position to horizontal position on top. This allows better navigation on recon data.
- Separate table for Directory scan results #244
- Scan results UI now in tabs
- Added badge on Subdomain Result table to directly query Vulnerability and Endpoints
- Webserver and content_type badge has been addeed in Subdomain Result table
- Inside Targets list, Recent Scan button has been added to quickly go to the last scan results
- In target summary, timelin of scan has been added
- Randomized user agent in HTTPX
- reNgine will no longer store any recon data apart from that in Database, this includes sorted_subdomains list.txt or any json file
- aquatone has been replaced with Eyewitness
- Out of Scope subdomains are no longer part of scan engine, they can be imported before initiating the scan
- Added script to uninstall reNgine
- Added option to filter targets and scans using organization, scan status, etc
- Added random user agent in directory scan
- Added concurrency, rate limit, timeout, retries in Scan Engine YAML
- Added Rescan option
- Other tiny fixes.....

### V0.5.3 Feb25 2021

- Build error for Naabu v2 Fixed
- Added rate support for Naabu

### V0.5.2 Feb 23 2021

- Fixed XSS <https://github.com/yogeshojha/rengine/issues/347>

### V0.5.1 Feb 19 2021

### Features (V0.5.1)

- Added Discord Support for Notification Web hooks

### V0.5 29 Nov 2020

### Features (V0.5)

- Nuclei Integration: v0.5 is primarily focused on vulnerability scanner using Nuclei. This was a long pending due and we've finally integrated it.

- Powerful search queries across endpoints, subdomains and vulnerability scan results: reNgine reconnaissance data can now be queried using operators like <,>,&,| and !, namely greater than, less than, and, or, and not. This is extremely useful in querying the recon data. More details can be found at Instructions to perform Queries on Recon data

- Out of scope options: Many of you have been asking for out of scope option. Thanks to Valerio Brussani for his pull request which made it possible for out of scope options. Please check the documentation on how to define out of scope options.

- Official Documentation(WIP): We often get asked on how to use reNgine. For long, we had no official documentation. Finally, I've worked on it and we have the official documentation at rengine.wiki

- The documentation is divided into two parts, for Developers and for Penetration Testers. For developers, it's a work in progress. I will keep you all updated throughout the process.

- Redefined Dashboard: We've also made some changes in the Dashboard. The additions include vulnerability scan results, most vulnerable targets, most common vulnerabilities.

- Global Search: This feature has been one of the most requested features for reNgine. Now you can search all the subdomains, endpoints, and vulnerabilities.

- OneForAll Support: reNgine now supports OneForAll for subdomain discovery, it is currently in beta. I am working on how to integrate OneForAll APIKeys and Configuration files.

- Configuration Support for subfinder: You will now have ability to add configurations for subfinder as well.

- Timeout option for aquatone: We added timeout options in yaml configuration as a lot of screenshots were missing. You can now define timeout for http, scan and screenshots for timeout in milliseconds.

- Design Changes A lot of design changes has happened in reNgine. Some of which are:

- Endpoints Results and Vulnerability Scan Results are now displayed as a separate page, this is to separate the results and decrease the page load time.
Checkbox next to Subdomains and Vulnerability report list to change the status, this allows you to mark all subdomains and vulnerabilities that you've already completed working on.
- Sometimes due to timeout, aquatone was skipping the screenshots and due to that, navigations between screenshots was little annoying. We have fixed it as well.
Ability to delete multiple targets and initiate multiple scans.

### Abandoned

- Subdomain Takeover: As we decided to use Nuclei for Vulnerability Scanner, and also, since Subjack wasn't giving enough results, I decided to remove Subjack. The subdomain Takeover will now be part of Nuclei Vulnerability Scanner.

### V0.4 Release 2020-10-08

### Features (V0.4)

- Background tasks migrated to Celery and redis
- Periodic and clocked scan added
- Ability to Stop and delete the scan
- CNAME and IP address added on detail scan
- Content type added on Endpoints section
- Ability to initiate multiple scans at a time

### V0.3 Release 2020-07-21

### Features (V0.3)

- YAML based Customization Engine
- Ability to add wordlists
- Login Feature

### V0.2 Release 2020-07-11

### Features (V0.2)

- Directory Search Enabled
- Fetch URLS using hakrawler
- Subdomain takeover using Subjack
- Add Bulk urls
- Delete Scan functionality

### Fix

- Windows Installation issue fixed
- Scrollbar Issue on small screens fixed

### V0.1 Release 2020-07-08

- reNgine is released
