# GRC

<figure><img src="https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/detail_what-is-grc.png" alt=""><figcaption></figcaption></figure>

***

### Security Principle: Access Control

Not everyone should have access to every document and information, right? Employees in the accounting department should not have access to human resources documents, and vice versa; individuals in human resources should not have access to accounting documents.The same principle applies to a computer network

Access control :

* governs the permissions for different individuals to access various information and resources within the network, specifying when and how they can do so.
* access control design can cause to unintended access to sensitive information by unauthorized individuals. This poses critical risks to the security of data, applications, and other resources within your network
* not only determines who can access which information, but also determines when and how users can access this information. This will help implement processes and policies better, comply with the regulations, and improve the overall security of your network

common approaches to access control are :

* RBAC (Role-Based Access Control)
* ABAC (Attribute-Based Access Control)

#### Role-Based Access Control (RBAC)



* used to determine users' authorization levels and the resources they can access. This ensures that the principle of least privilege is followed and that data privacy is protected.
* manages user or group access permissions to a system by assigning roles and associating them with specific permissions

#### Implementation of RBAC



1- **Defining the Role**\
**2- Assigning Users to Roles**\
**3- Authorization and Definition of Permissions**\
**4- Implementation of Access Control**\\

**Advantages of RBAC:**

* Enhances the organization of business and authorization processes.
* Management of user roles and permissions becomes easier.
* Provides security by preventing unauthorized access.
* Improves collaboration and operational efficiency.
* Provides traceability and compliance in internal and external audits.

\
ABAC :

* access control principle that permits us to define it through attribute-based access control
* flexible and effective access control mechanism that can respond to current security needs

***

### **Separation and the Principles of the Least Privilege**

\
&#xNAN;**(Separation of Duties)**

* the division of the permissions required to perform a task between people or roles.
* aims to prevent a single person or role from being able to perform all the tasks and to prevent potential malicious activities
* For instance, when an individual initiates a task, another person might be required to authorize or finalize it.

<figure><img src="https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/unnamed.gif" alt=""><figcaption></figcaption></figure>

**The Least Privilege :**

* simply providing users or roles only the minimum privileges necessary for their duties
* prevents data breaches and improves network security by limiting the authorization level.

<figure><img src="https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/images.jpg" alt=""><figcaption></figcaption></figure>

***

### Authentication



Strong Authentication Methods :

* Multi-Factor Authentication (MFA)
* Password Policies and Long, Complex Passwords
* Passwords should be changed periodically, stored securely, and should not be reused.
* Application of technological authentication methods such as biometric verification or physical devices.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/image6.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/image6.png)

***

### Session Management



Users' access should be granted for the required time period and the session should be terminated automatically. This measure safeguards against unauthorized access and mitigates the risk of session hijacking

implement control mechanisms :

**1. Starting a Session:** The session should start according to the conditions specified in the RBAC and/or ABAC part .

**2. Maintaining a Session:** The session should persist under the same conditions in which it was initiated.

**3. Session Monitoring:** During the session period, there should be no activity other than the scheduled permissions and privileges.

**4. Session Termination:** The session must be terminated properly.\\

Authorization and session managements are key elements of access control and are critical for a secure network infrastructure.

***

### Static and Dynamic Data



* **Static (stationary) data:** Static data, as its name suggests, remains stationary; it is stored somewhere, awaiting utilization. Examples include data on disks, etc. All forms of data residing in these kinds of environments fall within this category.
* **Dynamic data:** Dynamic data, as the name implies, is data that moves from one place to another. \[ This can also be a file downloaded to your system from an internet source ] \\

When the data is stored on the server (**static data**), it is protected using measures like network segmentation, RBAC, strong password policies, and multi-factor authentication. However, once the data is transferred between two locations (**dynamic data**), it travels through systems we cannot control. The only reliable way to secure it in transit is through **encryption**, ensuring that only the sender and the intended recipient can interpret it.

* **Static Data** → protected with access controls and permissions.
* **Dynamic Data** → protected with encryption during transmission.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/sni2.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/sni2.png)

#### Protection of Dynamic Data



* **Data Encryption**
* **Secure Data Communication \[** SSL/TLS protocols can be used , verification ]

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/image8.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/image8.png)

* make sure that the data is transferred and verified securely.
* not storing data unnecessarily.
* Data should be stored as long as necessary and should be purged regularly to reduce the risk of unnecessary retention
* the data must be stored securely for the duration of the retention period and access to the data must be restricted
* Data flow and sharing should be monitored, and unauthorized access attempts or data breaches should be detected.

\
Protection of Static Data

* **Data Encryption**
* **Access Controls \[** Defining user roles, permissions, and data restrictions ensures that only legitimate users have access to data ]
* **Data Backup and Recovery**
* Storage areas for static data should be secured with a combination of physical and electronic security measures
* Physical security includes measurements like secure data centers or server rooms, access controls, security cameras, and alarm systems. On the other hand, electronic measurements include strong encryption, firewalls, security tools, and intrusion detection systems.
* **Security Monitoring and Incident Response**
* **Data Deletion and Destruction**

***

### Authorization Methods



Authorization, which is performed after the authentication process, allows the users to determine the level of access to certain resources

Commonly used authorization approaches :\
1- **Role-Based Authorization**\
**2- Policy-Based Authorization**\
**3- Permission-Based Authorization**

\
**Role-Based Authorization :**

* Users gain access to certain resources in the system depending on their role.
* For example, users with an "Administrator" role can access all functions of the system, while users with a "User" role may be subject to certain restrictions

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/ab0d45a55f0c41a243093fb57d460fc366fed9ab-6336x3952.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/ab0d45a55f0c41a243093fb57d460fc366fed9ab-6336x3952.png)

\
**Policy-Based Authorization :**

* includes policy rules that determine users' access rights.
* For example, a policy rule may specify whether a particular user can access or not access a particular resource in a particular time zone.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/1751553018993.jpg)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/1751553018993.jpg)

**Permission-Based Authorization :**

* Users are given permissions to access certain resources or perform certain actions.
* For example, a user is given specific permissions to read, write, or delete a file.
* For example, user is included in an organization's guest network. After this process, the user is only authorized to read the files shared on the network\\

technologies and standards exist to support and implement the Authentication and Authorization processes :

* **LDAP (Lightweight Directory Access Protocol):** is a communication protocol used to retrieve user credentials from databases. It supports directory-based services used in the authentication and authorization processes of users.
* **Single Sign-On (SSO):** allows users to access multiple applications with a single authentication. Users authenticate once and then automatically gain access to other applications.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/auth3.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/auth3.png)

* Kerberos is a protocol used to provide secure authentication on a network. It is especially used in Windows-based systems and Active Directory environments
* **SAML (Security Assertion Markup Language):** is an XML-based standard used for authentication and authorization. Provides federation-based authentication where users are authenticated with a security statement provided by the identity provider to access a service

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/676ffeb1fa353f97be8f0246_61cc7d5ff16cb02316b7d847_SAML_20work.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/676ffeb1fa353f97be8f0246_61cc7d5ff16cb02316b7d847_SAML_20work.png)

* **RADIUS (Remote Authentication Dial-In User Service):** is a network protocol used for user authentication and authorization in remote access services. It is mainly used in network access points.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/RADIUS-Authentication-Process.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/RADIUS-Authentication-Process.png)

* OAuth : is an authorization protocol that allows users to be authorized to access a service. Used to control access to credentials of third-party applications.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/everything-you-need-to-know-about-oauth-4.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/everything-you-need-to-know-about-oauth-4.png)

* OpenID Connect is a standard that combines authentication and authorization processes based on the OAuth 2.0 protocol. It provides secure authentication of users through identity providers.
* **JWT (JSON Web Token):** JWT is an authentication mechanism used in web applications. It encrypts and securely transports user information in JSON format. These tokens enable secure sharing of authentication information

\{% embed url="[https://medium.com/@anas.abdo990088/jwt-from-a-blue-team-perspective-5f9f3d05c9b3](https://medium.com/@anas.abdo990088/jwt-from-a-blue-team-perspective-5f9f3d05c9b3)" %\}

\{% embed url="[https://medium.com/@anas.abdo990088/secrets-lab-blue-team-labs-online-7e7af65ea593](https://medium.com/@anas.abdo990088/secrets-lab-blue-team-labs-online-7e7af65ea593)" %\}

***

### Password Management



A strong and effective password management strategy is an essential step in ensuring the security of information, accounts, and systems.

Password Creation Policies :

* Regularly changing password
* storing passwords securely
* creating strong passwords
* two-factor authentication
* use unique passwords for each account
* **Automatic Password Generation Tools**

should include the basic principles of creating strong and secure passwords. Password generation principles basically consist of important items such as length, complexity, uniqueness, unpredictability, regular password updates, using automatic password generation tools, etc.

**Length:** It is important that passwords are too long to guess easily. It is generally recommended to be at least 12 characters long. Longer passwords provide more robust protection.

**Frequency of Updates :** How often passwords should be updated often depends on policies set by the organization. The recommended period is usually 90 days. However, in some cases, this period may be shorter or longer.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/pass1.jpeg)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/pass1.jpeg)

The following section is used to set a password policy on Windows.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/image4-1.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/image4-1.png)

The following file is used to set a password policy on Linux:

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/image4-2.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/image4-2.png)

login.defs : the name of the file used to set the password policy on Linux

the password policy you’re looking for (like **minimum numbers required in a password**) is usually defined in one of these files, not in the `/etc/pam.d/` folder itself.

* `/etc/pam.d/passwd` → runs when you change a password.
* `/etc/pam.d/sshd` → rules for SSH logins.
* `/etc/pam.d/system-auth` (RedHat/CentOS) or `/etc/pam.d/common-password` (Ubuntu/Debian) → global rules for password policies.

`/etc/pam.d/` VS `/etc/pam.d/`

**`/etc/pam.d/`**



* This is a **directory** that contains configuration files for **PAM (Pluggable Authentication Modules)**.
* PAM enforces complex password policies (like minimum number of digits, uppercase letters, minimum length, retries, etc.).

**`/etc/login.defs`**



* This is a **single configuration file** that controls more general user account settings.
* It does **not** control password complexity (like digits or uppercase letters)
* Examples of directives inside:
  * **PASS\_MAX\_DAYS** → maximum days a password is valid.
  * **PASS\_MIN\_DAYS** → minimum days before a password can be changed again.
  * **PASS\_WARN\_AGE** → how many days before expiration a warning is shown.
  * **UID\_MIN / UID\_MAX** → range of user IDs for regular users.

**Summary:**

* `/etc/pam.d/` → handles **password strength and quality rules**.
* `/etc/login.defs` → handles **password aging and user account defaults**.

\
Password Sharing and Communication :

* When passwords need to be shared, secure methods should be used. Sending passwords via email, instant messaging, or plain text are totally risky. Instead, it is important to use secure encryption protocols. For example, tools such as PGP (Pretty Good Privacy) can be used to send passwords encrypted. It is also a preferred method to securely share passwords face-to-face or with people you trust. This reduces the risk of the password being compromised by unauthorized persons.
* It is important to use secure communication tools such as encrypted messaging apps or virtual private networks (VPN).

#### Credential Harvesting Methods :



* **Phishing**
* **Keylogger**
* **Brute Force Attacks**
* **Dictionary Attack**
* **Social Engineering**

#### Precautions Against Password Threats



* It is important to use strong and complex passwords.
* It is important to change passwords regularly.
* Using multi-factor authentication increases security.
* Using secure internet connections reduces the risk of passwords being stolen.
* Risky connections such as public networks or unsafe Wi-Fi hotspots should be avoided.
* Using reliable and up-to-date anti-virus software prevents password theft attacks
