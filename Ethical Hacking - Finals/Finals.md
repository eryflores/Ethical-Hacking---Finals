# Ethical Hacking Technical Report
**Client:** YouTube  
**Date:** May 10, 2024  
**Prepared by:** Flores, Eryk Kyle James P. and Mencero, Micko  S.

## Executive Summary:
This report presents the technical findings of the ethical hacking assessment conducted for YouTube. The assessment aimed to identify vulnerabilities within the organization's network infrastructure, applications, and systems. Through various testing methodologies, including penetration testing and vulnerability scanning, critical and high-risk issues were discovered. This report provides detailed descriptions of these findings, along with actionable recommendations for remediation.

## Vulnerability Summary:
1. **Network Infrastructure:**
   - **Lack of robust firewall configuration:** Firewall rules are insufficiently restrictive, allowing potential attackers to exploit network vulnerabilities.
   - **Insufficient network segmentation:** Lack of segmentation increases the risk of lateral movement within the network in case of a breach.

2. **Web Applications:**
   - **Cross-Site Scripting (XSS) vulnerabilities:** Input fields are not properly sanitized, allowing attackers to inject malicious scripts.
   - **SQL Injection vulnerabilities:** Lack of input validation in SQL queries enables attackers to manipulate databases.

3. **Operating Systems:**
   - **Unpatched operating systems:** Known vulnerabilities in operating systems have not been addressed through patches, leaving systems vulnerable to exploitation.
   - **Weak or default passwords:** Administrative accounts have weak passwords or still use default credentials, making them easy targets for attackers.

4. **Wireless Networks:**
   - **ack of encryption and authentication protocols:** Wi-Fi networks are not adequately secured, exposing network traffic to interception and unauthorized access.
   - **Rogue access points:** Unauthorized access points within the network increase the attack surface and pose security risks.

5. **API Security:**
   - **Critical:** Lack of proper authentication and authorization controls in the API endpoints, leading to unauthorized access to user data and system resources.
   - **High:** Insufficient input validation in API requests, making them susceptible to injection attacks such as SQL Injection and NoSQL Injection.

6. **Sensitive Data Exposure:**
   - **Insecure Data Storage:** Sensitive information such as user credentials or payment details is stored in plaintext or inadequately encrypted format.
   -  **Excessive Data Retention:** SRetention of unnecessary sensitive data increases the risk of exposure in case of a breach.

7. **Code Injection:**
   - **Remote Code Execution (RCE):** Lack of input validation in user inputs or API parameters allows attackers to execute arbitrary code on the server.
   - **Command Injection:** Insufficient sanitization of user inputs in system commands leads to command injection vulnerabilities.

8. **Server-Side Request Forgery (SSRF):**
   - **Unrestricted URL Access:** Lack of proper input validation allows attackers to manipulate URLs and access internal resources.
   - **Information Disclosure:** Successful SSRF attacks can disclose sensitive information or lead to unauthorized access to internal systems.

9. **Cross-Site Scripting (XSS):**
   - **Stored XSS:** User-supplied data is not properly sanitized before being stored and displayed, allowing attackers to inject malicious scripts into web pages.
   - **Reflected XSS:** Lack of input validation and output encoding in user inputs leads to reflected XSS vulnerabilities.

0. **Insecure Cryptographic Implementations:**
   - **Weak Encryption Algorithms:** Use of outdated or weak encryption algorithms for data protection.
   - **Insecure Key Management:** Improper key management practices expose encrypted data to decryption attacks.

## Recommendations:
1. **Network Infrastructure:**
   - IStrengthen firewall rules to restrict unnecessary traffic.
   - Implement network segmentation to contain potential breaches.

2. **Web Applications:**
   - Implement input validation and output encoding to mitigate XSS vulnerabilities.
   - Use parameterized queries or ORM frameworks to prevent SQL injection attacks.

3. **Operating Systems:**
   - Apply patches regularly to mitigate known vulnerabilities.
   - Enforce strong password policies and implement multi-factor authentication.

4. **Wireless Networks:**
   - Upgrade wireless encryption protocols to WPA2 or WPA3.
   - Deploy wireless intrusion detection systems to monitor and detect unauthorized access points.

5. **API Security:**
   - Implement robust authentication and authorization mechanisms such as OAuth 2.0 to secure API endpoints.
   - Implement strict input validation and parameterized queries to mitigate injection attacks in API requests.

6. **Sensitive Data Exposure:**
   - Encrypt sensitive data at rest and in transit using strong encryption algorithms.
   - Implement data minimization practices to reduce the amount of sensitive data stored.

7. **Code Injection:**
   - Implement strict input validation and sanitization of user inputs to prevent code injection attacks.
   - Use safe APIs and frameworks that automatically mitigate common code injection vulnerabilities.

8. **Server-Side Request Forgery (SSRF):**
   - Implement URL whitelisting to restrict access to only trusted resources.
   - Conduct regular security assessments to identify and remediate SSRF vulnerabilities.

9. **Cross-Site Scripting (XSS):**
   - Implement input validation and output encoding to mitigate both stored and reflected XSS vulnerabilities.
   - Utilize Content Security Policy (CSP) to reduce the impact of XSS attacks.

0. **Insecure Cryptographic Implementations:**
   - Follow industry best practices for cryptographic algorithms and key management.
   - Regularly audit cryptographic implementations to identify and remediate weaknesses.

## Conclusion:
The findings of the ethical hacking assessment highlight several critical vulnerabilities and security weaknesses within YouTube's infrastructure and applications. By implementing the recommended remediation measures, YouTube can significantly enhance its security posture and mitigate the risk of cyber threats and data breaches.

**Signature:**  
Flores & Mencero
