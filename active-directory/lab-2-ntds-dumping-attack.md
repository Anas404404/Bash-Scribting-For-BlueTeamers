---
description: >-
  بسم الله والصلاة والسلام على رسول الله, اللهم علمنا ما ينفعنا وانفعنا بما
  علمتنا وقنا عذاب النار
---

# LAB 2 : NTDS dumping attack

<figure><img src="../.gitbook/assets/Screenshot 2025-10-06 at 11-03-35 .png" alt=""><figcaption></figcaption></figure>

Sherlock link :&#x20;

{% embed url="https://app.hackthebox.com/sherlocks/750" %}

```
Sherlock Scenario

Forela's Domain environment is pure chaos. Just got another alert from the Domain controller
of NTDS.dit database being exfiltrated. Just one day prior you responded to an alert on the
 same domain controller where an attacker dumped NTDS.dit via vssadmin utility. However, 
 you managed to delete the dumped files kick the attacker out of the DC, and restore a 
 clean snapshot. Now they again managed to access DC with a domain admin account with their
  persistent access in the environment. This time they are abusing ntdsutil to dump the database. 
  Help Forela in these chaotic times!!

```

***

```
Q1- When utilizing ntdsutil.exe to dump NTDS on disk, it simultaneously employs the Microsoft
 Shadow Copy Service. What is the most recent timestamp at which this service entered the
  running state, signifying the possible initiation of the NTDS dumping process?
```

**VssAdmin is used to create, delete, and list information about shadow copies. It can also be used to resize the shadow copy storage area (diff area). VssAdmin includes commands such as: create shadow : Creates a new shadow copy.**

**from "system" logs , filter with eventID : 7036**

<figure><img src="../.gitbook/assets/Screenshot (2306).png" alt=""><figcaption></figcaption></figure>

**ans ⇒ 2024-05-15 05:39:55**

***

```
Q2-Identify the full path of the dumped NTDS file
```

**from application logs , filter with eventID : 325 AND 327**

**It’s very important to pay attention to the timeline — the attacker created a Volume Shadow Copy and dumped ntds.dit at the same time.The VSS was created on 2024-05-15 at 05:39:55.**

<figure><img src="../.gitbook/assets/Screenshot (2308).png" alt=""><figcaption></figcaption></figure>

**We'll observe that this is not the original database from several angles:**

* **First: this is not its standard path — the expected location would be `c:\user\ntds.dit`, so this path is likely the attacker’s doing.**
* **Second: the timeline matches the time the attacker created the Volume Shadow Copy.**

**ans ⇒ C:\Windows\Temp\dump\_tmp\Active Directory\ntds.dit**

***

```
Q3- When was the database dump created on the disk?
```

<figure><img src="../.gitbook/assets/Screenshot (2309).png" alt=""><figcaption></figcaption></figure>

**ans ⇒ 2024-05-15 05:39:56**

***

```
Q4- When was the newly dumped database considered complete and ready for use?
```

**In this case, you should look for the logs related to:**

**“The database engine detached a database.”**

* **Event ID: 327**
* **Log Source:&#x20;**_**Application Logs**_

<figure><img src="../.gitbook/assets/Screenshot (2310).png" alt=""><figcaption></figcaption></figure>

ans ⇒ 2024-05-15 05:39:58

***

```
Q5- Event logs use event sources to track events coming from different sources. Which event 
source provides database status data like creation and detachment?
```

**from q1,2,3**&#x20;

**ans ⇒ ESENT**

***

```
When ntdsutil.exe is used to dump the database, it enumerates certain user groups to validate
the privileges of the account being used. Which two groups are enumerated by the ntdsutil.exe
 process? Give the groups in alphabetical order joined by comma space.
```

**from the "security" logs , eventid : 4799**

<figure><img src="../.gitbook/assets/Screenshot (2311).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/Screenshot (2312).png" alt=""><figcaption></figcaption></figure>

**logon ID : 0x8DE3D**

**ans ⇒ Administrators, Backup Operators**

***

```
Now you are tasked to find the Login Time for the malicious Session. Using the Logon ID,
find the Time when the user logon session started.
```

**this is a domain environment we would want to use Kerberos events , Logon IDs are used to track Logons on windows systems. We filter for Event ID 4768,4769 and 5379**

| Windows | [4768](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4768) | [A Kerberos authentication ticket (TGT) was requested](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4768) |
| ------: | :----------------------------------------------------------------------------------------------: | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Windows | [4769](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4769) | [A Kerberos service ticket was requested](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4769)              |
| Windows | [5379](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5379) | [Credential Manager credentials were read](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5379)             |

**Event ID 5379 right after kerberos events, same logonID**

<figure><img src="../.gitbook/assets/Screenshot (2314).png" alt=""><figcaption></figcaption></figure>

**ans ⇒ 2024-05-15 05:36:31**

***
