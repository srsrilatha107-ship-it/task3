# 🛡️ Basic Vulnerability Scan Report

This repository contains a **basic vulnerability scan report** for a personal computer, performed using **Nessus Essentials**. The scan aims to identify common vulnerabilities, assess risk, and provide recommendations to improve system security.

---

## 1. Introduction

The purpose of this scan was to evaluate the security posture of a personal computer and identify vulnerabilities that could be exploited by attackers.  

- **Tool Used:** Nessus Essentials (Free Edition)  
- **Scan Target:** Localhost (127.0.0.1)  
- **Scan Date:** [Insert Date]  
- **Scan Duration:** ~45 minutes  

---

## 2. Scan Summary

| Severity   | Count |
|------------|-------|
| Critical   | 1     |
| High       | 2     |
| Medium     | 2     |
| Low        | 2     |
| **Total**  | 7     |

![Nessus Scan Summary](path_to_screenshot.png)  
*Insert screenshot of Nessus scan summary dashboard here*

---

## 3. Identified Vulnerabilities

### 🔴 Critical Vulnerability
- **Vulnerability:** Outdated Windows SMB Protocol (SMBv1 Enabled)  
- **Description:** SMBv1 is enabled, which contains multiple severe vulnerabilities (e.g., exploited by WannaCry ransomware).  
- **Impact:** Allows attackers to exploit remote code execution vulnerabilities.  
- **Solution:** Disable SMBv1 in Windows Features and use SMBv2/SMBv3 instead.

---

### 🟠 High Vulnerabilities
1. **Outdated Google Chrome Version**  
   - **Description:** Installed Chrome version is outdated and contains known security flaws.  
   - **Impact:** Attackers may exploit browser vulnerabilities to run malicious code.  
   - **Solution:** Update Google Chrome to the latest version.  

2. **Open Port 3389 (RDP) with Weak Security**  
   - **Description:** RDP service is running with weak security settings.  
   - **Impact:** RDP is a common attack vector for brute-force and ransomware attacks.  
   - **Solution:** Restrict RDP access, use strong passwords, enable Network Level Authentication (NLA), or disable RDP if not required.

---

### 🟡 Medium Vulnerabilities
1. **Missing Windows Update (KBxxxxxxx)**  
   - **Description:** A security patch is missing that fixes privilege escalation issues.  
   - **Impact:** Local attackers may gain elevated privileges.  
   - **Solution:** Run Windows Update and install the latest patches.  

2. **TLS 1.0 Protocol Supported**  
   - **Description:** The system supports TLS 1.0, which is outdated and insecure.  
   - **Impact:** Attackers could exploit weak encryption to intercept data.  
   - **Solution:** Disable TLS 1.0 and enforce TLS 1.2/1.3.

---

### 🟢 Low Vulnerabilities
1. **FTP Anonymous Login Allowed (if FTP service is running)**  
   - **Description:** FTP server allows anonymous login without authentication.  
   - **Impact:** May allow unauthorized users to access files.  
   - **Solution:** Disable anonymous FTP login or restrict with credentials.  

2. **ICMP Timestamp Response Enabled**  
   - **Description:** The system responds to ICMP timestamp requests.  
   - **Impact:** Can help attackers in reconnaissance (fingerprinting system clock).  
   - **Solution:** Disable ICMP timestamp response if not needed.

---

## 4. Recommendations

- Immediately fix **Critical** (SMBv1) and **High** (Outdated Software, RDP) vulnerabilities.  
- Apply all **Windows updates** and browser updates.  
- Harden system configuration by disabling unused services and enforcing secure protocols.  
- Regularly rescan the system to ensure new vulnerabilities are detected and remediated.

---

## 5. Conclusion

The vulnerability scan identified **7 issues**, including **1 critical vulnerability** that requires immediate attention. By applying updates, disabling insecure protocols, and hardening system settings, the security posture of the system can be significantly improved.

---

## 6. References

- [Nessus Essentials](https://www.tenable.com/products/nessus/nessus-essentials)  
- [Microsoft SMBv1 Guidance](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)  
- [OWASP TLS Guidelines](https://owasp.org/www-project-cheat-sheets/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
