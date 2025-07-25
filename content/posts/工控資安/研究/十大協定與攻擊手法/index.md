---
title: "常見十大工控協定與攻擊手法"
date: 2024-03-21
categories: [OT Security]
tags: [Modbus, S7, DNP3]
---

# 常見十大工控協定與攻擊手法

### **Modbus 協定十大攻擊手法**

**1. 設備枚舉 (Device Enumeration)**

- **攻擊手法**: 透過系統性地發送讀取指令並遍歷所有可能的 Slave ID (0-247)，攻擊者可以掃描並繪製出整個 Modbus 網路的拓撲，識別所有在線的從站設備及其支援的資料區，為後續攻擊提供精確目標。
- **參考來源**:
  - CISA (Cybersecurity and Infrastructure Security Agency) - Control Systems Network Auditing: [https://www.cisa.gov/sites/default/files/recommended_practices/RP_Control_Systems_Network_Auditing_S508C.pdf](https://www.google.com/search?q=https://www.cisa.gov/sites/default/files/recommended_practices/RP_Control_Systems_Network_Auditing_S508C.pdf)
  - SANS Institute - ICS410: ICS/SCADA Security Essentials: [https://www.sans.org/cyber-security-courses/ics-scada-cyber-security-essentials/](https://www.sans.org/cyber-security-courses/ics-scada-cyber-security-essentials/)
  - Nmap Scripting Engine - modbus-discover.nse: [https://nmap.org/nsedoc/scripts/modbus-discover.html](https://nmap.org/nsedoc/scripts/modbus-discover.html)

**2. 未授權讀取 (Unauthorized Read)**

- **攻擊手法**: 由於 Modbus 協定本身缺乏認證機制，任何能連上網路的攻擊者都可以發送合法的讀取功能碼 (如 0x01, 0x02, 0x03, 0x04)，自由讀取設備的線圈和暫存器狀態，從而竊取關鍵的生產參數、設備組態或製程配方。
- **參考來源**:
  - Modbus-IDA - Modbus Application Protocol Specification V1.1b3: [https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
  - Fortinet - What Is the Modbus Protocol?: [https://www.fortinet.com/resources/cyberglossary/modbus-protocol](https://www.google.com/search?q=https://www.fortinet.com/resources/cyberglossary/modbus-protocol)
  - MITRE ATT\&CK for ICS - T0859 Read Input/Output Image: [https://collaborate.mitre.org/attackics/index.php/Technique/T0859](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0859)

**3. 惡意指令注入 (Command Injection)**

- **攻擊手法**: 攻擊者利用寫入功能碼 (如 0x05, 0x06, 0x0F, 0x10) 構造並發送惡意指令，直接竄改設備設定、控制邏輯或輸出狀態。這是最直接的攻擊方式，可能導致設備損壞或生產中斷。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0831 Manipulate Control Logic: [https://collaborate.mitre.org/attackics/index.php/Technique/T0831](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0831)
  - Claroty - Top 5 ICS Protocols and How to Secure Them: [https://claroty.com/resources/reports/top-5-ics-protocols-and-how-to-secure-them](https://www.google.com/search?q=https://claroty.com/resources/reports/top-5-ics-protocols-and-how-to-secure-them)
  - Dragos - TRITON - The First Malware Targeting Safety Instrumented Systems: [https://www.dragos.com/blog/triton-the-first-malware-targeting-safety-instrumented-systems/](https://www.google.com/search?q=https://www.dragos.com/blog/triton-the-first-malware-targeting-safety-instrumented-systems/)

**4. 阻斷服務 - 洪水攻擊 (DoS - Flooding)**

- **攻擊手法**: 以極高的頻率向目標設備發送大量合法的 Modbus 請求封包。這種洪水攻擊會耗盡設備有限的 CPU 或網路處理能力，使其無法回應來自合法 HMI 或主站的正常指令，造成服務阻斷。
- **參考來源**:
  - Nozomi Networks - Modbus Security Issues and How to Mitigate Cyber Risks: [https://www.nozominetworks.com/blog/modbus-security-issues-and-how-to-mitigate-cyber-risks/](https://www.google.com/search?q=https://www.nozominetworks.com/blog/modbus-security-issues-and-how-to-mitigate-cyber-risks/)
  - CISA Advisory - ICSA-19-142-01 Schneider Electric Modicon PLCs: [https://www.cisa.gov/news-events/ics-advisories/icsa-19-142-01](https://www.google.com/search?q=https://www.cisa.gov/news-events/ics-advisories/icsa-19-142-01)
  - NIST Special Publication 800-82 - Guide to Industrial Control Systems (ICS) Security: [https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final](https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final)

**5. 阻斷服務 - 畸形封包 (DoS - Malformed Packet)**

- **攻擊手法**: 攻擊者精心構造並發送不符合 Modbus 協定規範的封包，例如包含不合法的功能碼、錯誤的資料長度或無效的暫存器位址。這可能觸發設備韌體在解析封包時的錯誤，導致其當機或進入需手動重啟的鎖定狀態。
- **參考來源**:
  - CISA Advisory - ICSA-21-026-02 WAGO PFC Series Controllers: [https://www.cisa.gov/news-events/ics-advisories/icsa-21-026-02](https://www.cisa.gov/news-events/ics-advisories/icsa-21-026-02)
  - Research Paper (IEEE) - Vulnerabilities of the Modbus Protocol: [https://ieeexplore.ieee.org/document/4279093](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/4279093)

**6. 重放攻擊 (Replay Attack)**

- **攻擊手法**: 攻擊者在網路上錄製一段合法的通訊封包（例如啟動馬達、開啟閥門的指令），然後在稍後的惡意時間點將該封包原封不動地重播出去，造成非預期的物理操作。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0845 Replay: [https://collaborate.mitre.org/attackics/index.php/Technique/T0845](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0845)
  - SANS Institute - A Collection of Modbus Attacks (Whitepaper): [https://www.sans.org/white-papers/33631/](https://www.google.com/search?q=https://www.sans.org/white-papers/33631/)

**7. 緩衝區溢位攻擊 (Buffer Overflow)**

- **攻擊手法**: 利用特定功能碼（如 Write Multiple Registers），構造一個聲稱長度超大但實際資料很小的封包。如果設備韌體沒有對長度欄位進行嚴格檢查，就可能在複製資料時超出預期的記憶體緩衝區，觸發溢位漏洞，可能導致設備崩潰或被遠端執行程式碼。
- **參考來源**:
  - Digital Bond - Exploiting Modbus for Fun and Profit: [https://www.digitalbond.com/blog/2012/03/05/exploiting-modbus-for-fun-and-profit/](https://www.google.com/search?q=https://www.digitalbond.com/blog/2012/03/05/exploiting-modbus-for-fun-and-profit/)
  - CVE-2012-0210 (Example of a Modbus buffer overflow vulnerability): [https://nvd.nist.gov/vuln/detail/CVE-2012-0210](https://nvd.nist.gov/vuln/detail/CVE-2012-0210)

**8. 中間人攻擊 (Man-in-the-Middle)**

- **攻擊手法**: 攻擊者透過 ARP 欺騙或 DNS 劫持等技術，將自己置於合法主站和從站之間的通訊路徑上。這使得攻擊者可以攔截、竊聽甚至即時竄改雙向的通訊內容，例如修改回傳的溫度值或攔截停機指令。
- **參考來源**:
  - SANS Institute - Man-in-the-Middle Attacks on Modbus TCP: [https://www.sans.org/blog/man-in-the-middle-attacks-on-modbus-tcp/](https://www.google.com/search?q=https://www.sans.org/blog/man-in-the-middle-attacks-on-modbus-tcp/)
  - OWASP - Man-in-the-middle attack: [https://owasp.org/www-community/attacks/Man-in-the-middle_attack](https://www.google.com/search?q=https://owasp.org/www-community/attacks/Man-in-the-middle_attack)

**9. 會話劫持 (Session Hijacking)**

- **攻擊手法**: 在 Modbus TCP 環境中，攻擊者透過預測或竊取 TCP 的序列號，可以偽裝成合法的主站，在一個已建立的 TCP 連線中注入自己的惡意 Modbus 指令，從而劫持整個通訊會話。
- **參考來源**:
  - Armis - Pwned by the PLC: A New Attack Vector: [https://www.armis.com/research/pwned-by-the-plc/](https://www.google.com/search?q=https://www.armis.com/research/pwned-by-the-plc/)
  - Wikipedia - TCP sequence prediction attack: [https://en.wikipedia.org/wiki/TCP_sequence_prediction_attack](https://en.wikipedia.org/wiki/TCP_sequence_prediction_attack)

**10. 協定模糊測試 (Protocol Fuzzing)**

- **攻擊手法**: 使用自動化工具（如 Boofuzz）產生大量隨機、半隨機或基於規則變異的畸形 Modbus 封包，並將它們發送給目標設備。這種方法旨在系統性地探索設備韌體中未知的漏洞，特別是那些可能導致當機或非預期行為的解析錯誤。
- **參考來源**:
  - Research Paper (IEEE) - A Modbus/TCP Fuzzer for Field Device Penetration Testing: [https://ieeexplore.ieee.org/document/7468800](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/7468800)
  - Boofuzz Fuzzer Framework - GitHub: [https://github.com/jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz)
  - OWASP - Fuzzing: [https://owasp.org/www-community/Fuzzing](https://owasp.org/www-community/Fuzzing)

---

### **S7 協定十大攻擊手法**

**1. 設備指紋識別 (Device Fingerprinting)**

- **攻擊手法**: 透過主動發送 S7 查詢指令或被動分析通訊建立過程中的 COTP 和 S7COMM 標頭參數（如 TSAP），攻擊者可以精確地識別出目標 PLC 的型號、CPU 模組、韌體版本和組態資訊，為後續的精準攻擊提供情報。
- **參考來源**:
  - Nmap Scripting Engine - s7-info.nse: [https://nmap.org/nsedoc/scripts/s7-info.html](https://nmap.org/nsedoc/scripts/s7-info.html)
  - Research Paper (MDPI) - Vulnerability Analysis of S7 PLCs: [https://www.mdpi.com/1424-8220/21/21/7086](https://www.mdpi.com/1424-8220/21/21/7086)
  - SCADAhacker - Siemens S7 - Attacking and Fingerprinting (PDF): [https://scadahacker.com/library/Documents/ICS%20Protocols/Siemens%20S7%20-%20Attacking%20and%20Fingerprinting.pdf](https://www.google.com/search?q=https://scadahacker.com/library/Documents/ICS%2520Protocols/Siemens%2520S7%2520-%2520Attacking%2520and%2520Fingerprinting.pdf)

**2. 惡意程式下載 (Malicious Program Download)**

- **攻擊手法**: 這是 Stuxnet 蠕蟲的核心攻擊方式。攻擊者利用 S7 協定中合法的程式下載功能，將含有惡意邏輯（如後門、邏輯炸彈）的程式區塊 (OB, FC, FB) 注入到 PLC 中，從而徹底、持久地改變其行為。
- **參考來源**:
  - Langner Communications - To Kill a Centrifuge (Stuxnet Analysis): [https://www.langner.com/wp-content/uploads/2013/11/langner-stuxnet-breakthrough.pdf](https://www.google.com/search?q=https://www.langner.com/wp-content/uploads/2013/11/langner-stuxnet-breakthrough.pdf)
  - Claroty (Team82) - The Evil PLC Attack: [https://claroty.com/team82/research/the-evil-plc-attack-how-to-turn-a-passive-scanner-into-an-active-attacker](https://www.google.com/search?q=https://claroty.com/team82/research/the-evil-plc-attack-how-to-turn-a-passive-scanner-into-an-active-attacker)
  - MITRE ATT\&CK for ICS - T0843 Program Upload/Download: [https://collaborate.mitre.org/attackics/index.php/Technique/T0843](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0843)

**3. PLC 模式竄改 (PLC Mode Manipulation)**

- **攻擊手法**: 攻擊者在獲得 PLC 的連線權限後，發送特定的 S7COMM 指令，強制將 PLC 的運行模式從 RUN（運行）切換至 STOP（停止），或反之。此操作會立即中斷現場的生產流程，是一種直接且有效的阻斷服務攻擊。
- **參考來源**:
  - CVE-2014-2257 (Vulnerability example): [https://nvd.nist.gov/vuln/detail/CVE-2014-2257](https://www.google.com/search?q=https://nvd.nist.gov/vuln/detail/CVE-2014-2257)
  - Black Hat USA 2011 - S7-Slaying Presentation: [https://www.blackhat.com/presentations/bh-usa-11/Berrueta/BH_US_11_Berrueta_S7_Slaying_Slides.pdf](https://www.google.com/search?q=https://www.blackhat.com/presentations/bh-usa-11/Berrueta/BH_US_11_Berrueta_S7_Slaying_Slides.pdf)
  - MITRE ATT\&CK for ICS - T0815 Device Restart/Shutdown: [https://collaborate.mitre.org/attackics/index.php/Technique/T0815](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0815)

**4. 程式碼與資料竊取 (Code/Data Theft)**

- **攻擊手法**: 攻擊者利用協定中的讀取功能，未經授權地從 PLC 中讀取整個程式（所有 OB, FC, FB）和資料區塊 (DB)。這不僅會洩漏寶貴的控制邏輯和製程配方，也為離線分析漏洞和策劃後續攻擊提供了基礎。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0855 Read Program: [https://collaborate.mitre.org/attackics/index.php/Technique/T0855](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0855)
  - Siemens Product CERT - Security Advisory on Protection of Know-How: [https://cert-portal.siemens.com/productcert/pdf/ssa-632573.pdf](https://www.google.com/search?q=https://cert-portal.siemens.com/productcert/pdf/ssa-632573.pdf)
  - Wireshark Wiki - S7Comm Protocol: [https://wiki.wireshark.org/S7Comm](https://www.google.com/search?q=https://wiki.wireshark.org/S7Comm)

**5. 阻斷服務 - 協定層 (DoS - Protocol Layer)**

- **攻擊手法**: 向 S7 PLC 發送大量精心構造的畸形封包或高速發送合法的診斷請求，耗盡其 CPU 或記憶體資源。這會導致 PLC 無法處理正常的控制指令、與 HMI 的通訊中斷，或直接進入需要手動干預的缺陷 (defect) 模式。
- **參考來源**:
  - CISA Advisory - ICSA-14-353-01 Siemens S7-300/400 PLC Vulnerabilities: [https://www.cisa.gov/news-events/ics-advisories/icsa-14-353-01](https://www.google.com/search?q=https://www.cisa.gov/news-events/ics-advisories/icsa-14-353-01)
  - Dragos - CRASHOVERRIDE Analysis: [https://www.dragos.com/blog/crashoverride/crashoverride-analysis/](https://www.google.com/search?q=https://www.dragos.com/blog/crashoverride/crashoverride-analysis/)

**6. 重放攻擊 (Replay Attack)**

- **攻擊手法**: 由於 S7 協定缺乏足夠的防重放機制，攻擊者可以錄製一段關鍵操作的指令序列（例如 Stuxnet 中對變頻器頻率的修改指令），然後在不同時間點重播，以達到惡意操控的目的。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0845 Replay: [https://collaborate.mitre.org/attackics/index.php/Technique/T0845](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0845)
  - Kaspersky - Stuxnet: A Breakthrough: [https://securelist.com/stuxnet-a-breakthrough/29815/](https://www.google.com/search?q=https://securelist.com/stuxnet-a-breakthrough/29815/)

**7. 中間人攻擊 (Man-in-the-Middle)**

- **攻擊手法**: 攻擊者將自己置於工程師站/HMI 與 PLC 之間，攔截並即時竄改通訊內容。例如，可以向 PLC 傳送錯誤的指令，同時向 HMI 回傳正常的狀態值，從而欺騙操作員，隱藏攻擊行為。
- **參考來源**:
  - Kaspersky - The Siemens PLC Vulnerability: A Deep Dive: [https://www.kaspersky.com/blog/the-siemens-plc-vulnerability-a-deep-dive-into-industrial-cybersecurity/1155/](https://www.google.com/search?q=https://www.kaspersky.com/blog/the-siemens-plc-vulnerability-a-deep-dive-into-industrial-cybersecurity/1155/)
  - Claroty - Man-in-the-Middle Attacks in OT Networks: [https://claroty.com/resources/blog/man-in-the-middle-attacks-in-ot-networks](https://www.google.com/search?q=https://claroty.com/resources/blog/man-in-the-middle-attacks-in-ot-networks)

**8. 認證繞過 (Authentication Bypass)**

- **攻擊手法**: 針對具備存取保護功能的較新 S7-1200/1500 系列 PLC，攻擊者可能利用協議實作中的密碼學漏洞或弱密碼，繞過設定的讀寫保護或連線密碼，從而獲得未經授權的存取權限。
- **參考來源**:
  - Claroty (Team82) - New Critical Architectural Vulnerabilities in Siemens SIMATIC S7-1500 Series: [https://claroty.com/team82/research/new-critical-architectural-vulnerabilities-in-siemens-simatic-s7-1500-series-allow-for-bypass-of-all-protected-boot-features](https://www.google.com/search?q=https://claroty.com/team82/research/new-critical-architectural-vulnerabilities-in-siemens-simatic-s7-1500-series-allow-for-bypass-of-all-protected-boot-features)
  - CVE-2020-15782 (Cryptographic vulnerability example): [https://nvd.nist.gov/vuln/detail/CVE-2020-15782](https://nvd.nist.gov/vuln/detail/CVE-2020-15782)

**9. 時間戳偽造 (Timestamp Spoofing)**

- **攻擊手法**: 攻擊者在注入惡意指令的同時，可以竄改 S7 封包中的時間戳資訊。這會干擾 PLC 的事件順序記錄 (Sequence of Events, SOE) 功能，使得事後的故障分析和數位鑑識變得極其困難，有助於隱藏攻擊痕跡。
- **參考來源**:
  - Research Paper (Springer) - Forensic Analysis of Network-based Attacks on PLCs: [https://link.springer.com/chapter/10.1007/978-3-319-99076-9_12](https://www.google.com/search?q=https://link.springer.com/chapter/10.1007/978-3-319-99076-9_12)
  - SANS Institute - FOR578: Cyber Threat Intelligence: [https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/)

**10. 組態竄改 (Configuration Modification)**

- **攻擊手法**: 利用協定功能，未經授權地修改 PLC 的硬體組態、網路設定（如 IP 位址）、通訊夥伴關係或診斷緩衝區的設定。這種攻擊可能不會立即導致停機，但會為後續的攻擊或資訊竊取鋪平道路。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0836 Modify Parameter: [https://collaborate.mitre.org/attackics/index.php/Technique/T0836](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0836)
  - Siemens - TIA Portal Security in Practice: [https://support.industry.siemens.com/cs/document/109756633/tia-portal-security-in-practice](https://www.google.com/search?q=https://support.industry.siemens.com/cs/document/109756633/tia-portal-security-in-practice)

---

### **DNP3 協定十大攻擊手法**

**1. 未授權控制指令 (Unauthorized Control Command)**

- **攻擊手法**: DNP3 預設缺乏認證，攻擊者可直接發送 `Direct Operate` 或 `Select-Before-Operate` 等控制指令（如 Function Code 0x05, 0x06），遠端操作變電站的斷路器、開關等現場設備，可能引發大範圍電力中斷。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0816 Direct Output: [https://collaborate.mitre.org/attackics/index.php/Technique/T0816](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0816)
  - DNP Users Group - DNP3 Protocol Primer: [https://www.dnp.org/DNP3-Protocol-Primer](https://www.google.com/search?q=https://www.dnp.org/DNP3-Protocol-Primer)
  - Black Hat 2013 - DNP3 and the new "Smart Grid" (PDF): [https://www.blackhat.com/docs/us-13/US-13-Wilhoit-DNP3-See-You-Next-Fall-WP.pdf](https://www.google.com/search?q=https://www.blackhat.com/docs/us-13/US-13-Wilhoit-DNP3-See-You-Next-Fall-WP.pdf)

**2. 阻斷服務 - 輪詢洪水 (DoS - Integrity Poll Flood)**

- **攻擊手法**: 攻擊者向遠端終端單元 (RTU) 連續不斷地發送要求回報所有資料點的「完整性輪詢」請求 (Class 0 Poll)。這會強制 RTU 進行大量處理並發送大量資料，從而耗盡其資源並阻塞通訊網路。
- **參考來源**:
  - CISA Advisory - ICSA-12-045-01 DNP3 Security Risks: [https://www.cisa.gov/news-events/ics-advisories/icsa-12-045-01](https://www.google.com/search?q=https://www.cisa.gov/news-events/ics-advisories/icsa-12-045-01)
  - Research Paper (IEEE) - Risk Analysis of DNP3 Attacks: [https://ieeexplore.ieee.org/document/4212959](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/4212959)

**3. 資料偽造 (Data Injection/Spoofing)**

- **攻擊手法**: 攻擊者向主站 (Master) 發送偽造的量測值（如電壓、電流）或狀態點（如開關狀態）回報。這可以掩蓋真實的系統異常狀態，或觸發控制中心的錯誤告警，誤導操作員做出錯誤決策。
- **參考來源**:
  - NIST Special Publication 800-82 - Guide to Industrial Control Systems (ICS) Security: [https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final](https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final)
  - MITRE ATT\&CK for ICS - T0826 Inter-Process Communication: [https://collaborate.mitre.org/attackics/index.php/Technique/T0826](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0826)

**4. 畸形封包攻擊 (Malformed Packet Attack)**

- **攻擊手法**: 發送 CRC 校驗錯誤、資料連結層或應用層格式不符的封包。處理能力較弱的 RTU 在解析這些畸形封包時可能會發生錯誤，導致設備崩潰、重啟或停止回應，造成局部或全部監控中斷。
- **參考來源**:
  - CISA Advisory - ICSA-12-045-01 DNP3 Security Risks: [https://www.cisa.gov/news-events/ics-advisories/icsa-12-045-01](https://www.google.com/search?q=https://www.cisa.gov/news-events/ics-advisories/icsa-12-045-01)
  - Dragos - TRISIS/TRITON Malware Analysis: [https://www.dragos.com/blog/trisis-malware-the-third-scada-malware-and-second-ever-to-target-safety-instrumented-systems/](https://www.google.com/search?q=https://www.dragos.com/blog/trisis-malware-the-third-scada-malware-and-second-ever-to-target-safety-instrumented-systems/)

**5. 重放攻擊 (Replay Attack)**

- **攻擊手法**: 由於 DNP3 原始協定缺乏防重放機制，攻擊者可以錄製一段合法的指令封包（例如一個「跳閘」指令），然後在任何惡意時間點重播該封包，引發非預期的操作。
- **參考來源**:
  - Research Paper (IEEE) - A Security Evaluation of DNP3 Secure Authentication: [https://ieeexplore.ieee.org/document/7546416](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/7546416)
  - MITRE ATT\&CK for ICS - T0845 Replay: [https://collaborate.mitre.org/attackics/index.php/Technique/T0845](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0845)

**6. 設備枚舉 (Device Enumeration)**

- **攻擊手法**: 攻擊者發送 `Read Request` 並掃描不同的 Object Group 和 Class，可以探索目標 RTU 支援的所有資料點、功能以及其內部資料庫結構。這為後續的精準資料竊取或竄改攻擊提供了詳細的藍圖。
- **參考來源**:
  - SCADAhacker - SCADA Hacking: SCADA Protocols (DNP3) (Presentation): [https://www.slideshare.net/sushant7/scada-hacking-scada-protocols-dnp3](https://www.google.com/search?q=https://www.slideshare.net/sushant7/scada-hacking-scada-protocols-dnp3)
  - DNP Users Group - DNP3 Protocol Primer: [https://www.dnp.org/DNP3-Protocol-Primer](https://www.google.com/search?q=https://www.dnp.org/DNP3-Protocol-Primer)

**7. 檔案傳輸濫用 (File Transfer Abuse)**

- **攻擊手法**: DNP3 協定支援檔案傳輸功能。攻擊者可能濫用此功能，未經授權地從 RTU 下載敏感的組態檔案、日誌或密碼檔案，或者向 RTU 上傳惡意韌體或組態檔。
- **參考來源**:
  - Black Hat 2013 - DNP3 and the new "Smart Grid" (PDF): [https://www.blackhat.com/docs/us-13/US-13-Wilhoit-DNP3-See-You-Next-Fall-WP.pdf](https://www.google.com/search?q=https://www.blackhat.com/docs/us-13/US-13-Wilhoit-DNP3-See-You-Next-Fall-WP.pdf)
  - DNP3 Specification, Volume 6: File Transfer Procedures (Requires DNP membership)

**8. 認證繞過 (Authentication Bypass)**

- **攻擊手法**: 在部署了 DNP3-SA (安全認證) 的環境中，攻擊者可能利用協議實作中的漏洞、弱金鑰管理或透過重放攻擊，繞過安全認證機制，從而以看似合法的身份發送惡意指令。
- **參考來源**:
  - Research Paper (IEEE) - A Security Evaluation of DNP3 Secure Authentication: [https://ieeexplore.ieee.org/document/7546416](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/7546416)
  - CISA - Securing DNP3 and Other SCADA Protocols: [https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-12-020-01A](https://www.google.com/search?q=https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-12-020-01A)

**9. 廣播指令濫用 (Broadcast Command Abuse)**

- **攻擊手法**: DNP3 支援向廣播位址 (0xFFFF) 發送指令。攻擊者可以利用這一點，發送一個指令（如時間同步、凍結計數器）來一次性影響網路內所有的 DNP3 從站設備，可能造成大規模的同步混亂。
- **參考來源**:
  - Research Paper (IEEE) - DNP3 Protocol Security: [https://ieeexplore.ieee.org/document/4636306](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/4636306)
  - DNP Users Group - DNP3 Protocol Primer: [https://www.dnp.org/DNP3-Protocol-Primer](https://www.google.com/search?q=https://www.dnp.org/DNP3-Protocol-Primer)

**10. 中間人攻擊 (Man-in-the-Middle)**

- **攻擊手法**: 攻擊者將自己置於主站與 RTU 之間，攔截並即時修改通訊內容。例如，可以攔截一個查詢指令，然後自己偽造成 RTU 回應錯誤的資料給主站，或者修改主站發出的控制指令。
- **參考來源**:
  - NISTIR 7711 - Security Best Practice Recommendations for DNP3: [https://csrc.nist.gov/publications/detail/nistir/7711/final](https://csrc.nist.gov/publications/detail/nistir/7711/final)
  - SANS Institute - Securing Industrial Control Systems: [https://www.sans.org/cyber-security-courses/industrial-control-system-security/](https://www.google.com/search?q=https://www.sans.org/cyber-security-courses/industrial-control-system-security/)

---

### **Ethernet/IP 協定十大攻擊手法**

**1. 未授權標籤寫入 (Unauthorized Tag Write)**

- **攻擊手法**: 這是對 EtherNet/IP 最直接的攻擊。攻擊者利用 CIP (Common Industrial Protocol) 的 `Write Tag Service` 服務，在未經授權的情況下直接修改 PLC 中對應關鍵製程參數的標籤 (Tag) 值，如馬達轉速、閥門開度等。
- **參考來源**:
  - ODVA - Publication on CIP Security™: [https://www.odva.org/technology-standards/cip-security/](https://www.google.com/search?q=https://www.odva.org/technology-standards/cip-security/)
  - Forescout Research Labs - OT:ICEFALL Vulnerabilities: [https://www.forescout.com/resources/ot-icefall-vulnerabilities-re-discovery-and-re-packaging-of-insecure-by-design-vulnerabilities/](https://www.google.com/search?q=https://www.forescout.com/resources/ot-icefall-vulnerabilities-re-discovery-and-re-packaging-of-insecure-by-design-vulnerabilities/)
  - MITRE ATT\&CK for ICS - T0831 Manipulate Control Logic: [https://collaborate.mitre.org/attackics/index.php/Technique/T0831](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0831)

**2. 阻斷服務 - 連線耗盡 (DoS - Connection Exhaustion)**

- **攻擊手法**: 攻擊者透過發送大量的未連接訊息 (UCMM) 或建立大量 CIP 連線，可以迅速耗盡目標設備有限的連線資源或 CPU 處理能力，導致其無法處理即時的 I/O 通訊，造成產線停機。
- **參考來源**:
  - Claroty (Team82) - Attacking EtherNet/IP: [https://claroty.com/team82/research/attacking-ethernet-ip](https://www.google.com/search?q=https://claroty.com/team82/research/attacking-ethernet-ip)
  - CISA Advisory - ICSA-21-252-01 Rockwell Automation Logix Controllers: [https://www.cisa.gov/news-events/ics-advisories/icsa-21-252-01](https://www.cisa.gov/news-events/ics-advisories/icsa-21-252-01)

**3. 設備指紋識別 (Device Fingerprinting)**

- **攻擊手法**: 攻擊者使用 CIP 的 `ListIdentity` 指令或向特定物件發送 `Get_Attribute_Single` 請求，可以獲取設備的供應商、產品名稱、型號、序列號、韌體版本等詳細資訊，為尋找已知漏洞提供依據。
- **參考來源**:
  - ODVA - The CIP Networks Library, Volume 1: Common Industrial Protocol: [https://www.odva.org/library-and-know-how/](https://www.google.com/search?q=https://www.odva.org/library-and-know-how/) (Requires membership)
  - Nmap Scripting Engine - enip-info.nse: [https://nmap.org/nsedoc/scripts/enip-info.html](https://nmap.org/nsedoc/scripts/enip-info.html)

**4. 惡意韌體更新 (Malicious Firmware Update)**

- **攻擊手法**: 攻擊者可能利用協定中合法的韌體更新機制，向 PLC 或 I/O 模組上傳一個惡意或已損壞的韌體。成功後，可以使設備永久失效（變磚），或在其中植入難以檢測的後門。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0819 Firmware Tampering: [https://collaborate.mitre.org/attackics/index.php/Technique/T0819](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0819)
  - CISA Advisory - ICSA-16-133-02 Rockwell Automation ControlLogix: [https://www.cisa.gov/news-events/ics-advisories/icsa-16-133-02](https://www.google.com/search?q=https://www.cisa.gov/news-events/ics-advisories/icsa-16-133-02)

**5. 組態修改 (Configuration Modification)**

- **攻擊手法**: 攻擊者利用 TCP/IP 物件等 CIP 物件，未經授權地修改設備的 IP 位址、網路遮罩、通訊速率等網路組態。這可能導致設備脫離網路，或被重導向到一個惡意的網路環境中。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0836 Modify Parameter: [https://collaborate.mitre.org/attackics/index.php/Technique/T0836](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0836)
  - Rockwell Automation - Securing Your EtherNet/IP Network (Publication): [https://literature.rockwellautomation.com/idc/groups/literature/documents/rm/1756-rm095\_-en-p.pdf](https://literature.rockwellautomation.com/idc/groups/literature/documents/rm/1756-rm095_-en-p.pdf)

**6. 中間人攻擊 (Man-in-the-Middle)**

- **攻擊手法**: 由於 EtherNet/IP 的即時 I/O 資料（隱式報文）預設不加密，攻擊者可以透過 ARP 欺騙等方式攔截這些流量，並即時注入錯誤的感測器讀值或竄改輸出指令，直接干擾物理製程。
- **參考來源**:
  - ODVA - Publication on CIP Security™: [https://www.odva.org/technology-standards/cip-security/](https://www.google.com/search?q=https://www.odva.org/technology-standards/cip-security/)
  - SANS Institute - Securing Industrial Control Systems: [https://www.sans.org/cyber-security-courses/industrial-control-system-security/](https://www.google.com/search?q=https://www.sans.org/cyber-security-courses/industrial-control-system-security/)

**7. 重放攻擊 (Replay Attack)**

- **攻擊手法**: 攻擊者錄製一段有效的 I/O 資料通訊封包，然後在之後的時間點重播。這會使控制器接收到過時或不正確的現場狀態，可能導致其基於錯誤的資訊做出誤判。
- **參考來源**:
  - MITRE ATT\&CK for ICS - T0845 Replay: [https://collaborate.mitre.org/attackics/index.php/Technique/T0845](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0845)
  - Research Paper (IEEE) - Security Analysis of EtherNet/IP: [https://ieeexplore.ieee.org/abstract/document/6685671](https://www.google.com/search?q=https://ieeexplore.ieee.org/abstract/document/6685671)

**8. 會話劫持 (Session Hijacking)**

- **攻擊手法**: 攻擊者透過竊聽或預測，獲取一個合法的 CIP 連線的會話控制代碼 (Session Handle)，然後偽造成合法端點，在該會話中發送自己的惡意指令，從而劫持整個通訊。
- **參考來源**:
  - ODVA - The CIP Networks Library, Volume 1 (Details on session management): [https://www.odva.org/library-and-know-how/](https://www.google.com/search?q=https://www.odva.org/library-and-know-how/)
  - Wikipedia - Session hijacking: [https://en.wikipedia.org/wiki/Session_hijacking](https://en.wikipedia.org/wiki/Session_hijacking)

**9. 標籤讀取與資訊洩漏 (Tag Reading & Info Leakage)**

- **攻擊手法**: 與寫入攻擊相對應，攻擊者利用 `Read Tag Service` 讀取所有可存取的標籤。這不僅能獲取即時狀態，還可能竊取儲存在控制器中的製程配方、批次號、操作員指令等商業機密或敏感資訊。
- **參考來源**:
  - Claroty (Team82) - Attacking EtherNet/IP: [https://claroty.com/team82/research/attacking-ethernet-ip](https://www.google.com/search?q=https://claroty.com/team82/research/attacking-ethernet-ip)
  - MITRE ATT\&CK for ICS - T0859 Read Input/Output Image: [https://collaborate.mitre.org/attackics/index.php/Technique/T0859](https://www.google.com/search?q=https://collaborate.mitre.org/attackics/index.php/Technique/T0859)

**10. 協定模糊測試 (Protocol Fuzzing)**

- **攻擊手法**: 針對 CIP 協定的各個服務、物件類別和參數進行模糊測試，發送大量畸形封包，以尋找可能導致控制器或 I/O 模組崩潰、無回應或進入非預期狀態的未知漏洞。
- **參考來源**:
  - DEF CON 23 - Fuzzing and Crashing the PLC: [https://www.youtube.com/watch?v=k-FG2jJenrM](https://www.google.com/search?q=https://www.youtube.com/watch%3Fv%3Dk-FG2jJenrM)
  - Synopsys - Defensics Fuzzer: [https://www.synopsys.com/software-integrity/security-testing/fuzz-testing.html](https://www.synopsys.com/software-integrity/security-testing/fuzz-testing.html)

---

### **OPC UA 協定十大攻擊手法**

**1. 阻斷服務 - 會話洪水 (DoS - Session Flood)**

- **攻擊手法**: 攻擊者向 OPC UA 伺服器並發地發送大量 `CreateSession` 請求。由於伺服器能維持的會話數量有限，這種攻擊會迅速耗盡其會話資源，導致合法用戶端無法建立新的連線，造成服務阻斷。
- **參考來源**:
  - BSI (German Federal Office for Information Security) - Study on the Security of OPC UA (PDF): [https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf?\_\_blob=publicationFile\&v=3](https://www.google.com/search?q=https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf%3F__blob%3DpublicationFile%26v%3D3)
  - Research Paper (IEEE) - Covert Timing Channel Attack on OPC UA-based ICS: [https://ieeexplore.ieee.org/document/9083204](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/9083204)

**2. 中間人攻擊 - 憑證偽造 (MITM - Certificate Forgery)**

- **攻擊手法**: 攻擊者產生一個偽造的伺服器憑證，並利用 DNS 欺騙等方式將用戶端導向自己。如果用戶端沒有正確驗證伺服器憑證的信任鏈，就會與攻擊者建立連線，所有通訊內容將被竊聽或竄改。
- **參考來源**:
  - Research Paper (MDPI) - A Comprehensive Formal Security Analysis of OPC UA: [https://www.mdpi.com/2410-387X/3/3/23](https://www.mdpi.com/2410-387X/3/3/23)
  - OPC Foundation - OPC UA Security In a Nutshell (PDF): [https://opcfoundation.org/wp-content/uploads/2020/07/OPC-UA-Security-In-a-Nutshell.pdf](https://www.google.com/search?q=https://opcfoundation.org/wp-content/uploads/2020/07/OPC-UA-Security-In-a-Nutshell.pdf)

**3. 中間人攻擊 - TLS 降級 (MITM - TLS Stripping)**

- **攻擊手法**: 攻擊者攔截用戶端與伺服器之間的連線建立過程，欺騙雙方使用一個較弱的安全策略（如 `None`，即不加密不簽章），或阻止加密連線的建立。這會將原本安全的通訊降級為明文傳輸，便於竊聽。
- **參考來源**:
  - BSI - Study on the Security of OPC UA: [https://www.bsi.bund.de/EN/Topics/Industry_40/OPC_UA_Security/opc_ua_security_node.html](https://www.google.com/search?q=https://www.bsi.bund.de/EN/Topics/Industry_40/OPC_UA_Security/opc_ua_security_node.html)
  - Moxie Marlinspike - SSL Stripping: [https://moxie.org/software/sslstrip/](https://www.google.com/search?q=https://moxie.org/software/sslstrip/)

**4. 惡意方法呼叫 (Malicious Method Call)**

- **攻擊手法**: OPC UA 允許伺服器定義可供用戶端呼叫的方法 (Method)。攻擊者在獲得足夠權限後，可以呼叫這些方法並傳入惡意或非預期的參數，從而觸發伺服器端的危險操作，例如刪除歷史資料、修改組態或執行系統命令。
- **參考來源**:
  - OPC Foundation - OPC UA Specification Part 4: Services: [https://reference.opcfoundation.org/v104/Core/docs/Part4/5.11/](https://www.google.com/search?q=https://reference.opcfoundation.org/v104/Core/docs/Part4/5.11/)
  - BSI - Study on the Security of OPC UA (PDF): [https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf?\_\_blob=publicationFile\&v=3](https://www.google.com/search?q=https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf%3F__blob%3DpublicationFile%26v%3D3)

**5. 權限繞過 (Authorization Bypass)**

- **攻擊手法**: 攻擊者利用伺服器在節點存取控制設定上的漏洞（例如，父節點設為拒絕存取，但子節點忘了設定而繼承了預設的允許存取），以一個低權限使用者身份，成功讀寫到本應受保護的高權限節點資料。
- **參考來源**:
  - BSI - Study on the Security of OPC UA: [https://www.bsi.bund.de/EN/Topics/Industry_40/OPC_UA_Security/opc_ua_security_node.html](https://www.google.com/search?q=https://www.bsi.bund.de/EN/Topics/Industry_40/OPC_UA_Security/opc_ua_security_node.html)
  - Research Paper (IEEE) - Assessing the impact of attacks on OPC-UA applications: [https://ieeexplore.ieee.org/document/8993809](https://ieeexplore.ieee.org/document/8993809)

**6. 憑證與私鑰竊取 (Certificate & Private Key Theft)**

- **攻擊手法**: OPC UA 的安全高度依賴於 X.509 憑證和對應的私鑰。攻擊者透過入侵伺服器或用戶端主機，從檔案系統或作業系統的憑證儲存區中竊取這些憑證檔案。一旦得手，攻擊者便可完美地偽冒被盜主機的身份。
- **參考來源**:
  - OPC Foundation - Practical Security Recommendations for building OPC UA applications: [https://opcfoundation.org/wp-content/uploads/2020/07/OPC-UA-Security-Practical-Recommendations.pdf](https://www.google.com/search?q=https://opcfoundation.org/wp-content/uploads/2020/07/OPC-UA-Security-Practical-Recommendations.pdf)
  - NIST - Public Key Infrastructure (PKI) Basics: [https://www.nist.gov/itl/applied-cybersecurity/pki/pki-basics](https://www.google.com/search?q=https://www.nist.gov/itl/applied-cybersecurity/pki/pki-basics)

**7. 端點枚舉 (Endpoint Enumeration)**

- **攻擊手法**: 攻擊者首先向 OPC UA 的發現端點 (Discovery Endpoint) 發送 `GetEndpoints` 請求，以探索伺服器支援的所有安全策略與端點。這可以幫助攻擊者找到設定最弱、最容易攻擊的端點（如 `SecurityPolicy=None`）進行連線。
- **參考來源**:
  - OPC Foundation - OPC UA Specification Part 4: Services (GetEndpoints): [https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.4/](https://reference.opcfoundation.org/v104/Core/docs/Part4/5.4.4/)
  - BSI - Study on the Security of OPC UA (PDF): [https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf?\_\_blob=publicationFile\&v=3](https://www.google.com/search?q=https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf%3F__blob%3DpublicationFile%26v%3D3)

**8. 資訊洩漏 (Information Disclosure)**

- **攻擊手法**: 攻擊者透過 `Browse` 和 `Read` 服務，遞迴地遍歷伺服器的整個位址空間 (Address Space)。這會洩漏系統的完整架構、所有節點的名稱、資料類型和關係，為後續的精準攻擊提供詳細的情報。
- **參考來源**:
  - BSI - Study on the Security of OPC UA: [https://www.bsi.bund.de/EN/Topics/Industry_40/OPC_UA_Security/opc_ua_security_node.html](https://www.google.com/search?q=https://www.bsi.bund.de/EN/Topics/Industry_40/OPC_UA_Security/opc_ua_security_node.html)
  - OPC Foundation - OPC UA Specification Part 4: Services (Browse): [https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.2/](https://reference.opcfoundation.org/v104/Core/docs/Part4/5.8.2/)

**9. 畸形訊息攻擊 (Malformed Message Attack)**

- **攻擊手法**: 攻擊者發送結構複雜（如深度遞迴的節點篩選器）或格式錯誤的訊息，利用伺服器解析器的漏洞觸發崩潰、資源耗盡或非預期的行為。這通常是透過模糊測試 (Fuzzing) 發現的。
- **參考來源**:
  - Research Paper (IEEE) - Fuzzing for vulnerability and compliance analysis in OPC-UA: [https://ieeexplore.ieee.org/document/8413550](https://www.google.com/search?q=https://ieeexplore.ieee.org/document/8413550)
  - CISA Advisory - ICSA-21-062-01 Multiple OPC UA Stacks: [https://www.cisa.gov/news-events/ics-advisories/icsa-21-062-01](https://www.google.com/search?q=https://www.cisa.gov/news-events/ics-advisories/icsa-21-062-01)

**10. 會話劫持 (Session Hijacking)**

- **攻擊手法**: 攻擊者透過網路竊聽等方式，竊取一個已經過認證的會話 Token (`authenticationToken`)。然後，攻擊者可以在該會話的生命週期內，利用這個 Token 冒充合法使用者向伺服器發送請求，從而劫持會話。
- **參考來源**:
  - OPC Foundation - OPC UA Specification Part 4: Services (ActivateSession): [https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.3/](https://reference.opcfoundation.org/v104/Core/docs/Part4/5.6.3/)
  - BSI - Study on the Security of OPC UA (PDF): [https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf?\_\_blob=publicationFile\&v=3](https://www.google.com/search?q=https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/OPC_UA_Security/OPC_UA_Security_Study.pdf%3F__blob%3DpublicationFile%26v%3D3)
