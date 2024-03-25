# CompTIA-Security
This document contains the notes I used for the Security+ exam
___
# -Fundamentals of Security
## Balancing Security vs Usability/Convenience
### Threat:
Anything that could cause harm, loss, damage, or compromise to information technology systems such as natural disasters, cyber-attacks, data integrity breaches, disclosure of confidential information
### Vulnerability:
Any weakness in the system design or implementation such as software bugs, misconfigured software, improperly protected network devices, missing security patches, lack of physical security
### Risk Management:
Finding different ways to minimize the likelihood of an outcome occurring and achieve the desired outcomes
### Information Security:
#### Protecting the data
Act of protecting data and information from unauthorized access, unlawful modification and disruption, disclosure, and corruption, and destruction.
### Information Systems Security:
#### Devices that hold the data
Act of protecting the systems that hold and process the critical data
### CIA Triad:
#### Confidentiality:
Ensures that information is only accessible to those with the appropriate authorization
- Protect personal privacy
- Maintain a business advantage
- Achieve regulatory compliance
##### Measures:
- **Encryption**: Process of converting data into code to prevent unauthorized access
- Access Controls: Ensure only authorized personnel can access certain types of data
- Data Masking: Method that involves obscuring data within a database to make it inaccessible for unauthorized users while retaining the real data's authenticity and use for authorized users
- Physical Security Measures: Used to ensure confidentiality for physical types of data and for digital information contained on servers and workstation
- Training and Awareness: Conducting regular training on the security awareness best practices that employees can use to protect the organization's sensitive data
#### Integrity:
Ensures that data remains accurate and unaltered unless modification is required
- Ensure data accuracy
- Maintain trust
- Ensure system operability
##### Measures:
- **Hashing**: Process of converting data into a fixed-size value
- Digital Signatures: Use encryption to ensure integrity and authenticity
- Checksums: Method to verify the integrity of data during transmission
- Access Controls: Ensure that only authorized individuals can modify data and reduce the risk of unintentional or malicious alterations
- Regular Audits: Involve reviewing logs and operations to ensure that only authorized changes have been made and any discrepancies are addressed
#### Availability:
Ensures that information and resources are accessible and functional when needed by authorized users
- Ensuring business continuity
- Maintain customer trust
- Upholding an organization's reputation
##### Measures:
- **Redundancy**: Duplication of critical components or functions of a system with the intention of enhancing its reliability
	- Server redundancy: Using multiple servers in a load balance so that if one is overloaded or fails, the other servers can take over the load to continue supporting end users
	- Data redundancy: Involves storing data in multiple places
	- Network redundancy: Ensures that if one network path fails, the data can travel through another route
	- Power redundancy: Using backup power sources to ensure that an organization's systems remain operational during periods of power disruption or outages within a local service area
### Non-repudiation:
#### Added to CIA Triad
Guaranteeing that a specific action or event has taken place and cannot be denied by the parties involved
- Confirming the authenticity of digital transactions
- Ensuring integrity
- Providing accountability
##### Measures:
- **Digital Signature**: Created by first hashing a particular message or communication to be digitally signed and encrypting the hash digest with the user's private key using asymmetric encryption
### Authentication:
#### Added to CIA Triad
Process of verifying the identity of a user or system
- Knowledge factors - Something you know
- Possession factors - Something you have
- Inherence factors - Something you are
- Action factors - Something you do
- Location factors - Somewhere you are
##### Measures:
2FA/MFA
##### Goals:
1. Prevent unauthorized access
2. Protect user data and privacy
3. Ensure resource validity
### Authorization:
Defines what actions or resources a user can access
##### Goals:
1. Protect sensitive data
2. Maintain system integrity in organizations
3. Create more streamlined user experiences
### Accounting:
Act of tracking user activities and resource usage, typically for audit or billing purposes
- Transparency
- Security
- Accountability
##### Measures:
- Syslog servers: Used to aggregate logs from various network devices and systems so that system administrators can analyze them to detect patterns or anomalies in the organization's systems
- Network analysis tools: Used to capture and analyze network traffic to gain detailed insights into all the data moving within a network
- SIEMs: Provides real-time analysis of security alerts generated by various hardware and software infrastructures in an organization
##### Goals:
- Audit trail: Provides chronological record of all user activities that can be used to trance changes, unauthorized access ,or anomalies back to a specific user or point in time
- Regulatory compliance: Maintains a comprehensive record of all the users' activities
- Forensic analysis: Uses detailed accounting and event logs that can help cybersecurity experts understand what happened, how it happened, and how to prevent similar incidents from occurring again in the future
- Resource optimization: Organizations can optimize system performance and minimize costs by tracking resource utilization and allocation decisions
- User accountability: Thorough accounting system ensures users' actions are monitored and logged, deterring potential misuse and promoting adherence to the organization's policies

### Security Controls:
Measures or mechanisms put in place to mitigate risks and protect the confidentiality, integrity, and availability of information systems and data
#### Categorical:
##### Technical:
The technologies, hardware, and software mechanisms that are implemented to manage and reduce risks
- Antivirus
- Firewalls
- Encryption processes
- IDS
##### Managerial:
Involve the strategic planning and governance side of security which also encompass security policies, training programs, and incident response strategies
##### Operational:
Procedures and measures that are designed to protect data on a day-to-day basis and are mainly governed by internal processes and human actions
- Password TTL
- Backup procedures
- Account reviews
- User training programs
##### Physical:
Tangible, real-world measures taken to protect assets
- Shredding of sensitive documents
- Security guards
- Locking doors
#### Types:
##### Preventative:
Proactive measures implemented to thwart potential security threats or breaches
##### Deterrent:
Aim to discourage potential attackers by making the effort seem less appealing or more challenging
##### Detective:
Monitor and alert organizations to malicious activities as they occur or shortly thereafter
##### Corrective:
Mitigate any potential damage and restore the systems to their normal state
##### Compensating:
Alternative measures that are implemented when primary security controls are not feasible or effective
##### Directive:
Often rooted in policy or documentation and set the standards for behavior within an organization
### Gap Analysis
Process of evaluating the differences between an organization's current performance and its desired performance
##### Steps:
1. Define the scope of the analysis
2. Gather data on the current state of the organization
3. Analyze the data to identify the gaps
4. Develop a plan to bridge the gap
##### Types:
- Technical gap analysis: Involves evaluating an organization's current technical infrastructure and identifying any areas where it falls short of the technical capabilities required to fully utilize their security solutions
- Business gap analysis: Involves evaluating an organization's current business processes and identifying any areas where they fall short of the capabilities required to fully utilize cloud-based solutions
###### Used to develop Plan of Action and Milestones (POA&M):
Outlines the specific measures to address each vulnerability, allocate resources, and set up timelines for each remediation task that is needed
### Zero Trust:
Security model that operates on the principle that no one, whether inside or outside the organization, should be trusted by default
#### Control Plane:
Consists of the adaptive identity, threat scope reduction, policy-driven access control, and secured zones
- Adaptive identity: Use adaptive identities that rely on real-time validation that takes into account the user's behavior, device, location, and other factors
- Threat scope reduction: Limit the users' access to only what they need for their work tasks because this drastically reduces the network's potential attack surface
- Policy-driven access control: Entails developing, managing, and enforcing user access policies based on their roles and responsibilities
- Secured zones: Isolated environments within a network that are designed to house sensitive data
#### Data Plane:
Focused on the subject/system, policy engine, policy administrator, and establishing policy enforcement points
- Subject/System: Refers to the individual or entity attempting to gain access
- Policy engine: Cross-references the access request with its pre-defined policies
- Policy administrator: Used to establish and manage the access policies
- Policy enforcement point: Allow or restrict access, and it will effectively act as a gatekeeper to the sensitive areas of the systems or networks

___
#  Threat Actors
## An individual or entity responsible for incidents that impact security and data protection
### Motivations:
#### Types:
- Data exfiltration: The unauthorized transfer of data from a computer
- Financial gain: One of the most common motivations for cybercriminals
- Blackmail: The attacker obtains sensitive or compromising information about an individual or an organization and threatens to release this information to the public unless certain demands are met
- Service disruption: Often achieved by conducting a DDoS attack to overwhelm a network, service, or server with excessive amounts of traffic so that it becomes unavailable to its normal users
- Philosophical or political beliefs: Individuals or groups use hacking to promote a political agenda, social change, or to protect against organizations they perceive as unethical
- Ethical reasons: Ethical hackers, also known as Authorized hackers, are motivated by a desire to improve security
- Revenge: An employee who is disgruntled, or one who has recently been fired or laid off, might want to harm their current or former employer by causing a data breach, disrupting services, or leaking sensitive information
- Disruption or chaos: These actors, often referred to as Unauthorized hackers, engage in malicious activities for the thrill of it, to challenge their skills, or simply to cause harm
- Espionage: Involves spying on individuals, organizations, or nations to gather sensitive or classified information
- War: Cyberattacks have increasingly become a tool for nations to attack each other
### Attributes:
- Internal Threat Actors: Individuals or entities within an organization who pose a threat to its security
- External Threat Actors: Individuals or groups outside an organization who attempt to breach its cybersecurity defenses
- Resources and Funding: Refers to the tools, skills, and personnel at the disposal of a given threat actor
- Level of Sophistication and Capability: Refers to their technical skill, the complexity of the tools and techniques they use, and their ability to evade detection and countermeasures
### Unskilled Attacker (Script Kiddie):
An individual who lacks the technical knowledge to develop their own hacking tools or exploits (for recognition or curiosity)
- DDoS attacks
### Hacktivists:
Individuals or groups that use their technical skills to promote a cause or drive social change instead of for personal gain (for ideological beliefs)
- Website defacement
- DDoS attacks
- Doxing
- Leaking of sensitive data
### Organized Crime:
Sophisticated and well-structured entities that leverage resources and technical skills for illicit gain (for financial gain)
- Custom malware
- Ransomware
- Sophisticated phishing campaigns
### Nation-State Actors:
Groups that are sponsored by a government to conduct cyber operations against other nations, organizations, or individuals (for political gain)
- False flag attack: Attack that is orchestrated in such a way that it appears to originate from a different source or group
- Advanced persistent threat (APT): Term that used to be used synonymously with a nation-state actor because of their long-term persistence and stealth
### Insider threats:
Cybersecurity threats that originate from within the organization
- Data theft
- Sabotage
- Misuse of access privileges
#### Driven by:
1. Financial gain
2. Revenge
3. Carelessness or lack of awareness
### Shadow IT:
The use of information technology systems, devices, software, applications, and services without explicit organizational approval
- Use of personal devices for work
- Installation of unapproved software (plugins, extensions)
- Use of cloud services that have not been approved
### Threat Vectors (How) and Attack Surfaces (Where):
The means or pathway by which an attacker can gain unauthorized access to a computer or network to deliver a malicious payload or carry out an unwanted action
#### Mitigated by:
- Restricting access
- Removing unnecessary software
- Disabling unused protocols
#### Types of Threat Vectors:
- Messages: SMS or phishing emails
- Images: Embedding malicious code
- Files: Malicious files
- Voice calls: Vishing
- Removable devices: USBs (baiting)
- Unsecure networks: Intercept data, BlueBorne (vulnerabilities in BT), BlueSmack (DoS)
### Outsmarting Threat Actors:
#### Deception/Disruption technologies:
Designed to mislead, confuse, and divert attackers from critical assets while simultaneously detecting and neutralizing threats
- Honeypots: Decoy system or network
- Honeynets: Network of honeypots to mimic an entire network
- Honeyfiles: Decoy file to lure potential attackers (Word docs, spreadsheets, presentations, images, databases, executables)
- Honeytokens: Piece of data or resource that has no legitimate value
##### Methods:
- Using bogus DNS entries
- Creating decoy directories
- Generating dynamic page
- Using port triggering
- Spoofing telemetry data
#### Tactics, Techniques, and Procedures (TTPs):
Specific methods and patterns of activities or behaviors associated with a particular threat actor or group of threat actors
___
# Physical Security
### Fencing (for personnel):
#### Purposes:
1. Provide a visual deterrent by defining a boundary that should not be violated by unauthorized personnel
2. Establishes a physical barrier against unauthorized entry
3. Delays intruders, which helps provide security personnel with a longer window of time to react
#### Protects against:
- Trespassing
- Theft
- Vandalism
- Unauthorized facility access
### Bollards (for vehicles):
#### Purpose:
To keep vehicles away from buildings so that if an IED explodes nearby, the building and people are safe
1. Creates a physical barrier that shields pedestrians, structures, and other assets from potential vehicular collisions
2. Serves a secondary purpose as a clear visual reminder of where vehicles are not permitted
### Brute Force:
Attack where access to a system is gained by trying all of the possibilities until breaking through
#### Types:
- Forcible entry: Act of gaining unauthorized access to a space by physically breaking or bypassing its barriers, such as windows, doors, or fences
	- Reinforcing is used to counter
- Tampering with security devices: Involves manipulating security devices to create new vulnerabilities that can be exploited
	- Redundancy is used to counter
- Confronting security personnel: Involves the direct confrontation or attack of security personnel
	- Training staff is used to counter
- Ramming a barrier with a vehicle: Brute force attack that uses a car, truck, or other motorized vehicle to ram into the organization's physical security barriers
	- Bollards are used to counter
### Surveillance Systems:
Maintain the security and safety of facilities, including business, home, or commonly used public areas
#### Categories:
- Video surveillance
- Security guards
- Lighting
- Sensors
### Bypassing Surveillance Systems:
#### Methods:
- Visual obstruction: Blocking a camera's LOS
- Blinding sensors and cameras: Overwhelming the sensor
- Acoustic interference: Jamming or playing loud sounds
- Electromagnetic interference: Jamming the signals
- Physical environment attack: Exploiting the environment
#### Counter-measures:
- Tamper alarms
- Backup power supplies/UPS
- Encrypt frequencies
### Access Control Vestibules:
Double-door system that is designed with two doors that are electronically controlled to ensure that only one door can be opened at a given time
#### Piggybacking:
Person with legitimate access intentionally allows another person without authorization to enter a secure area with them
#### Tailgating:
Unauthorized person follows someone with legitimate access to the secure space without their knowledge or consent
#### Counter-measures:
- RFID
- NFC
- Mag strips
### Door Locks:
Physical security control that is designed to secure entryways by restricting and regulating access to a particular space or property
#### Challenges:
- False Acceptance Rate (FAR): The rate that the system authenticates a user as valid, even though that person should not have been granted access to the system
- False Rejection Rate (FRR): Occurs any time biometrics system denies a user who should have been allowed access to the system
- Equal Error Rate (EER): More commonly called Crossover Error Rate (CER), which uses a measure of the effectiveness of a given biometrics system to achieve a balance
#### Other type of door lock:
A cipher lock provides excellent protection using a mechanical locking mechanism with push buttons that are numbered and require a person to enter the correct combination in order to open that door
### Access Badge Cloning:
Refers to copying the data from an RFID or NFC card or badge onto another card or device
#### Steps Involved:
1. Scanning: An attacker can use a handheld RFID or NFC reader to capture data from a victim's card and store it for further processing
2. Data Extraction: Once the data is captured, attackers extract the relevant authentication credentials from the card
3. Writing to a new card: Using specialized writing tools, the attacker will then transfer the extracted data into a blank RFID or NFC card
4. Using a cloned access badge: Now that the attacker has their cloned access badge or device in hand, they can gain unauthorized access to buildings, computer systems, or even make payments
#### Counter-measures:
1. Implement advanced encryption in card-based authentication systems
2. Implement MFA
3. Regularly update security protocols
4. Educate the users
5. Users should implement the use of shielded wallets or sleeves with RFID access badges
6. Monitor and audit the access logs
___
# Social Engineering
### Motivational Triggers:
- Authority: The power or right to give orders, make decisions, and enforce obedience
- Urgency: Compelling sense of immediacy of time-sensitivity that drives individuals to act swiftly or prioritize certain actions
- Social Proof: Psychological phenomenon where individuals look to the behaviors and actions of others to determine their own decisions or actions in similar situations
- Scarcity: Psychological pressures people feel when they believe a product, opportunity, or resource is limited or in short supply
- Likability: It is associated with being nice, friendly, and socially accepted by others
- Fear: Feeling afraid of someone or something, as likely to be dangerous, painful, or threatening
### Impersonation:
- Impersonation: An attack where an adversary assumes the identity of another person to gain unauthorized access to resources or steal sensitive data
- Brand Impersonation: Specific form of impersonation where an attacker pretends to represent a legitimate company or brand
- Typosquatting: A form of cyber attack where an attacker registers a domain name that is similar to a popular website but contains some kind of common typographical errors
- Watering Hole Attacks: Targeted of cyber attack where attackers compromise a specific website or service that their target is known to use
### Pretexting:
Train the employees not to fall for pretext and to not fill in the gaps for people when they are calling
### Phishing Attacks:
- Phishing: Fraudulent attack using deceptive emails from trusted sources to trick individuals into disclosing personal information like passwords and credit card numbers
- Vishing: Phone-based attack in which the attacker deceives victims into divulging personal or financial information
- Smishing: Attack that uses text messages to decode individuals into sharing their personal information
- Whaling: Form of spear phishing that targets high-end profile individuals like CEOs and CFOs
- Spear Phishing: Used by cybercriminals who are more tightly focused on a specific group of individuals or organization
- Business Email Compromise (BEC): Advanced phishing attack that leverages internal email accounts within a company to manipulate employees into carrying out malicious actions for the attacker
### Preventing Phishing Attacks:
- Conduct training: Vital tool for educating individuals about phishing risks and how to recognize potential phishing attempts in user security awareness training
- Recognize phishing attempts: Urgency, unusual requests, mismatched URLs, strange email addresses, poor spelling and grammar
- Reporting: Report suspicious messages to protect your organization from potential phishing attacks
### Frauds and Scams:
#### Fraud:
The wrongful or criminal deception intended to result in financial or personal gain
- Identity Fraud: The use by one person of another person's personal information, without authorization, to commit a crime or to deceive or defraud that other person or a third person
- Identity Theft: Attacker tries to full assume the identity of their victim
#### Scam:
A fraudulent or deceptive act or operation
### Influence Campaigns:
Influence campaigns can foster misinformation and disinformation
#### Misinformation:
Inaccurate information shared unintentionally
#### Disinformation:
Intentional spread of fake information to deceive or mislead
### Other Social Engineering Attacks:
- Diversion Theft: Manipulating a situation or creating a distraction to steal valuable items or information
- Hoaxes: Malicious deception that is often spread through social media, email, or other communication channels
- Shoulder Surfing: Looking over someone's shoulder to gather personal information
- Dumpster Diving: Searching through trash to find valuable information
- Eavesdropping: The process of secretly listening to private conversations
- Baiting: Planting a malware-infected device for a victim to find and unintentionally introduce malware to their organization's system
- Piggybacking or Tailgating: Both involve an unauthorized person following an authorized person into a secure area
___
# Malware
### Viruses:
Malicious code that's run on a machine without the user's knowledge and this allows the code to infect the computer whenever it has been run
- Boot sector: Stored in the first sector of a hard drive and is then loaded into memory whenever the computer boots up
- Program: Tries to find executables or application files to infect with their malicious code
- Encrypted: Designed to hide itself from being detected by encrypting its malicious code or payloads to avoid detection by any antivirus software
- Metamorphic: Able to rewrite itself entirely before it attempts to infect a given file
- Armor: Have a layer of protection to confuse a program or a person who's trying to analyze it
- Macro: A form of code that allows a virus to be embedded inside another document so that when the document is opened by the user, the virus is executed
- Multipartite: A combination of boot sector type virus and a program virus
- Polymorphic: Advanced version of an encrypted virus, but instead of just encrypting the contents, it will actually change the virus's code each time it is executed by altering the decryption module in order for it to evade detection
- Stealth: Not necessarily a specific type of virus as much as it is a technique used to prevent the virus from being detected by the anti-virus software 
- Hoax: A form of technical social engineering that attempts to scare end users into taking undesirable action on their system
### Worms:
Piece of malicious software, much like a virus, but it can replicate itself without any user interaction
#### Dangerous for these reasons:
1. Can infect the workstation and other computing assets
2. Can cause disruptions to the normal network traffic since they are constantly trying to replicate and spread across the network
### Trojans:
A piece of malicious software that is disguised as a piece of harmless or desirable software
#### Remote Access Trojan (RAT):
Type of Trojan that is widely used by modern attackers because it provides the attacker with remote control of a victim machine
### Ransomware:
Type of malicious software that is designed to block access to a computer system or its data by encryption it until a ransom is paid to the attacker
#### Best Practices:
- Conducting regular backups
- Installing regular software updates
- Providing security awareness training
- Implementing MFA
#### Affected by Ransomware:
- Never pay the ransom
- Disconnect the infected system from the network
- Notify authorities
- Restore the data from known good backups
### Zombies and Botnets:
#### Zombie:
Used to perform the task using remote commands from the attacker without the user's knowledge
#### Botnet:
Used for cyberattacks or other malicious activities
### Rootkits:
Type of software that is designed to gain administrative-level control over a given computer system without being detected
#### Shim:
Software code that is placed between two components
### Backdoor and Logic Bombs:
#### Backdoor:
Used to bypass the normal security and authentication functions (RAT, Easter Eggs)
#### Logic Bomb:
Malicious code that's inserted into a program, and will only execute when certain conditions have been met
### Keylogger:
Piece of software or hardware that records every single keystroke that is made on a computer or mobile device
#### Counter-measures:
- Perform regular updates and patches
- Rely on quality antivirus and anti malware solutions
- Conduct phishing awareness training for all end users
- Implement MFA
- Encrypt keystrokes being sent to systems
- Perform physical checks of desktops, laptops, and servers
### Spyware and Bloatware:
#### Spyware:
Type of malicious software that is designed to gather and send information about a user or organization
##### Methods of delivery:
- Bundled with other software
- Installed through a malicious website
- Installed when users click on a deceptive pop-up ad
#### Bloatware:
Any software that comes pre-installed on a new computer or smartphone
### Malware Attack Techniques:
#### Fileless Malware:
Used to create a process in the system memory without relying on the local file system of the infected host
##### Stages:
1. Dropper or Downloader
2. Second-stage downloader
3. "Actions on objectives" phase
4. Concealment
### Indications of Malware Attacks:
- Account lockouts
- Concurrent session utilization
- Blocked content
- Impossible travel
- Resource consumption
- Resource inaccessibility
- Out-of-cycle logging
- Missing logs
- Published or documented attacks
___
# Data Protection
### Data Classifications
Category based on the organization's value and the sensitivity of the information if it were to be disclosed
#### Sensitive Data:
Any information that can result in a loss of security or a loss of advantage to a company if accessed by an unauthorized person
#### Commercial Business Classifications:
- Public: No impact if released
- Sensitive: Minimal impact
- Private: Data that should only be used within the organization
- Confidential: Trade secrets, IP, etc.
#### Government Classifications:
- Unclassified
- Sensitive but Unclassified
- Confidential: Seriously affect the government
- Secret: Seriously damage national security
- Top Secret: Damage national security
### Data Ownership
Process of identifying the person responsible for the confidentiality, integrity, availability, and privacy of the information assets
- Data Owner: Senior executive role that has the responsibility for maintaining the confidentiality, integrity, and availability of the information asset
- Data Controller: Entity that holds responsibility for deciding the purposes and methods of data storage, collection, and usage, and for guaranteeing the legality of processes
- Data Processor: Group or individual hired by the data controller to help with tasks like collecting, storing, or analyzing data
- Data Custodian: Responsible for handling the management of the system on which the data assets are stored (system administrator)
- Data Steward: Focused on the quality of the data and the associated metadata
- Data Privacy Officer: Role that is responsible for the oversight of any kind of privacy-related data, like PII, SPI, or PHI
### Data States
#### Data at Rest:
Refers to any data stored in databases, file systems, or other storage systems
- Full disk encryption
- Partition encryption
- File encryption
- Volume encryption
- Database encryption
- Record encryption
#### Data in Transit:
Refers to data actively moving from one location to another, such as across the Internet or through a private network
- SSL/TLS
- VPN
- IPSec
#### Data in Use:
Refers to data in the process of being created, retrieved, updated, or deleted
- Application level
- Access controls
- Secure enclaves
- Intel software guards
### Data Types
#### Regulated Data:
Information controlled by laws, regulations, or industry standards
#### Trade Secrets:
Type of confidential business information that provides a company with a competitive edge
#### Intellectual Property:
Creation of the mind, such as inventions, literary, and artistic works, designs, and symbols
#### Legal Information:
Includes any data related to legal proceedings, contracts, or regulatory compliance
#### Financial Information:
Includes data related to an organization's financial transactions, such as sales records, invoices, tax, documents, and bank statements
#### Human-Readable Data:
Information that can be understood by humans without the need for a machine software
#### Non-Human Readable Data:
Information that requires a machine or software to interpret
### Data Sovereignty
Refers to the concept that digital information is subject to the laws of the country in which it is located
### Securing Data
#### Geographic Restrictions:
Involves setting up virtual boundaries to restrict data access based on geographic location
#### Encryption:
Fundamental data security method that transforms readable data (plaintext) into unreadable data (ciphertext) using an algorithm and an encryption key
#### Hashing:
Technique that converts data into a fixed size of numerical or alphanumeric characters known as a hash value
#### Masking:
Involves replacing some or all of the data in a field with a placeholder, such as "x", to conceal the original content
#### Tokenization:
Replaces sensitive data with non-sensitive substitutes, known as tokens
#### Obfuscation:
Involves making data unclear or unintelligible, making it difficult for unauthorized users to understand
#### Segmentation:
Involves dividing a network into separate segments, each with its own security controls
#### Permission Restrictions:
Involves defining who has access to specific data and what they can do with it
### Data Loss Prevention (DLP)
Set up to monitor the data of a system while it's in use, in transit, or at rest in order to detect any attempts to steal the data
#### Endpoint DLP System:
A piece of software that's installed on a workstation or a laptop, and it's going to monitor the data that's in use on that computer
#### Network DLP System:
A piece of software or hardware that's a solution placed at the perimeter of the network to detect data in transit
#### Storage DLP:
 A software that is installed on a server in the data center and inspects the data while it's at rest on the server
#### Cloud-based DLP System:
Usually offered as SaaS, and it's part of the cloud service and storage needs
___
# -Cryptographic Solutions
### Symmetric vs Asymmetric
#### Symmetric Encryption (Private Key):
Encryption algorithm in which both the sender and receiver must know the same shared secret using a single privately held key
#### Asymmetric Encryption (Public Key):
Encryption algorithm where different keys are used to encrypt and decrypt the data
#### Hybrid Implementation:
Utilizes asymmetric encryption to securely transfer a private key that can be used with symmetric encryption
#### Stream Cipher:
Utilizes a keystream generator to encrypt data bit by using a mathematical XOR function to create the ciphertext
#### Block Cipher:
Breaks the input into fixed-length blocks of data and performs the encryption on each block
### Symmetric Algorithms
#### DES:
Encryption algorithm which breaks the input into 64-bit blocks and uses transposition and substitution to create ciphertext using an effective key strength of only 56-bits
#### Triple DES (3DES):
Encryption algorithm which uses three separate symmetric keys to encrypt, decrypt, then encrypt the plaintext into ciphertext in order to increase the strength of DES
#### International Data Encryption Algorithm (IDEA):
Symmetric block cipher which uses 64-bit blocks to encrypt plaintext into ciphertext
#### Advanced Encryption Standard (AES):
Symmetric block cipher that uses 128-bit, 192-bit, or 256-bit blocks and a matching encryption key size to encrypt plaintext into ciphertext
#### Blowfish:
Symmetric block cipher that uses 64-bit blocks and a variable length encryption key to encrypt plaintext into ciphertext
#### Twofish:
Provides the ability to use 128-bit blocks in its encryption algorithm and uses 128-bit, 192-bit, or 256-bit encryption keys
#### Rivest Ciphers (RC4, RC5, RC6):
##### RC Cipher Suite:
Created by Ron Rivest, a cryptographer who's created six algorithms under the name RC which stands for the Rivest Cipher
##### Rivest Cipher (RC4):
Symmetric stream cipher using a variable key size from 40-bits to 2048-bits that is used in SSL and WEP
##### Rivest Cipher (RC5):
Symmetric block cipher that uses key sizes up to 2048-bits
##### Rivest Cipher (RC6):
Symmetric block cipher that was introduced as a replacement for DES but AES was chosen instead
### Asymmetric Algorithms
#### Digital Signature:
A hash digest of a message encrypted with the sender's private key to let the recipient know the document was created and sent by the person claiming to have sent it
#### Diffie-Hellman (DH):
Used to conduct key exchanges and secure key distribution over an unsecure network
1. Asymmetric algorithm
2. Used for the key exchange inside of creating a VPN tunnel establishment as part of IPSec
#### Rivest, Shamir, and Adleman (RSA):
Asymmetric algorithm that relies on the mathematical difficulty of factoring large prime numbers
#### Elliptic Curve Cryptography (ECC):
Heavily used in mobile devices and it's based on the algebraic structure of elliptical curve over finite fields to define its keys
#### Elliptic Curve Diffie-Hellman (ECDH):
ECC version of the popular Diffie-Hellman key exchange protocol
#### Elliptic Curve Diffie-Hellman Ephemeral (ECDHE):
Uses a different key for each portion of the key establishment process inside the Diffie-Hellman key exchange
#### Elliptic Curve Digital Signature Algorithm (ECDSA):
Used as a public key encryption algorithm by the US Government in their digital signatures
### Hashing
One-way cryptographic function that takes an input and produces a unique message digest as its output
#### MD5:
Creates a 128-bit hash value that is unique to the input file
#### SHA-1:
Creates a 160-bit hash digest, which significantly reduces the number of collisions that occur
#### SHA-2:
Family of hash functions that contain longer has digests
#### SHA-3:
Newer family of hash functions, and its hash digest can go between 224 bits and 512 bits
#### RACE Integrity Primitive Evaluation Message Digest (RIPEMD):
Comes in 160-bit, 256-bit, and 320-bit versions
##### RIPEMD-160:
Open-source hashing algorithm that was created as a competitor to the SHA family
#### Hash-based Message Authentication Code (HMAC):
Used to check the integrity of a message and provides some level of assurance that its authenticity is real
#### Digital Security Standard (DSS):
Relies upon a 160-bit message digest created by the Digital Security Algorithm
### Increasing Hash Security
#### Pass the Hash Attack:
Hacking technique that allows the attacker to authenticate to a remote server or service by using the underlying hash of a user's password instead of requiring the associated plaintext password
##### Mimikatz
Provides the ability to automate the process of harvesting the hashes and conducting the attack
#### Birthday Attack:
Occurs when an attacker is able to send two different messages through a hash algorithm and it results in the same identical hash digest, referred to as a collision
#### Key Stretching:
Technique that is used to mitigate a weaker key by increasing the time needed to crack it
#### Salting:
Adding random data into a one-way cryptographic hash to help protect against password cracking techniques
### Public Key Infrastructure (PKI)
An entire system of hardware, software, policies, procedures, and people that is based on asymmetric encryption
#### Certificate Authority:
Issues digital certificates and keeps the level of trust between all of the certificate authorities around the world
#### Key Escrow:
Process where cryptographic keys are stored in a secure, third-party location, which is effectively an "escrow"
### Digital Certificates
Digitally signed electronic document that binds a public key with a user's identity
#### Wildcard Certificates:
Allows all of the subdomains to use the same public key certificate and have it displayed as valid
##### Subject Alternate Name SAN Field:
Certificate that specifies what additional domains and IP addresses are going to be supported
#### Single-Sided Certificates:
Only requires the server to be validated
#### Dual-Sided Certificates:
Requires both the server and the user to be validated
#### Self-Signed Certificates:
Digital certificate that is signed by the same entity whose identity it certifies
#### Third-Part Certificates:
Digital certificate issued and signed by a trusted certificate authority (CA)
#### Root of Trust:
Each certificate is validated using the concept of a root of trust or the chain of trust
#### Registration Authority:
Requests identifying information from the user and forwards that certificate request up to the certificate authority to create the digital certificate
#### Certificate Signing Request:
A block of encoded text that contains information about the entity requesting the certificate
#### Certificate Revocation List:
Serves as an online list of digital certificates that the certificate authority has already revoked
#### Online Certificate Status Protocol (OSCP):
Allows to determine the revocation status of any digital certificate using its serial number
#### OSCP Stapling:
Allows the certificate holder to get the OSCP record from the server at regular intervals
#### Public Key Pinning:
Allows an HTTPS websites to resist impersonation attacks from users who are trying to present fraudulent certificates
#### Key Escrow:
Occurs when a secure copy of a user's private key is being held
#### Key Recovery Agents:
Specialized type of software that allows the restoration of a lost or corrupted key to be performed
### Blockchain
A shared immutable ledger for recording transactions, tracking assets, and building trust
#### Public Ledger:
A record-keeping system that maintains participants' identities in a secure and anonymous format
#### Smart Contracts:
Self-executing contracts where the terms of agreement or conditions are written directly into lines of code
#### Permissioned Blockchain:
Used for business transactions and it promotes new levels of trust and transparency using this immutable public ledgers
### Encryption Tools
#### Trusted Platform Module (TPM):
Dedicated microcontroller designed to secure hardware through integrated cryptographic keys
#### Hardware Security Module (HSM):
Physical device that safeguards and manages digital keys, primarily used for mission-critical situations like financial transactions
#### Key Management System:
Integrated approach for generating, distributing, and managing cryptographic keys for devices and applications
#### Secure Enclave:
Co-processor integrated into the main processor of some devices, designed with the sole purpose of ensuring data protection
### Obfuscation
#### Steganography:
Derived from Greek words meaning "covered writing," and it is all about concealing a message within another so that the very existence of the message is hidden
#### Tokenization:
Transformative technique in data protection that involves substituting sensitive data elements with non-sensitive equivalents, called tokens, which have no meaningful value
#### Data Masking:
Used to protect data by ensuring that it remains recognizable but does not actually include sensitive information
### Cryptographic Attacks
Techniques and strategies that adversaries employ to exploit vulnerabilities in cryptographic systems with the intent to compromise the confidentiality, integrity, or authenticity of data
#### Downgrade Attack:
Aims to force a system into using a weaker or older cryptographic standard or protocol than what it's currently utilizing
#### Collision Attack:
Aims to find two different inputs that produce the same hash output
#### Quantum Computing:
A computer that uses quantum mechanics to generate and manipulate quantum bits (qubits) in order to access enormous processing powers
#### Quantum Communication:
A communication network that relies on qubits made of photons (light) to send multiple combinations of ones and zeros simultaneously which results in tamper resistant and extremely fast communications
#### Qubit:
A quantum bit composed of electrons or photons that can represent numerous combinations of ones and zeros at the same time through superposition
#### Post-Quantum Cryptography:
A new kind of cryptographic algorithm that can be implemented using today's classical computers but is also impervious to attacks from future quantum computers
- Increase key size
- Other approaches (researchers are working on)
#### General Encryption Needs:
- CRYSTALS-Dilithium
- FALCON
- SPHINCS+
___
# -Risk Management
### Risk Assessment Frequency
The regularity with which risk assessments are conducted within an organization
#### Ad-Hoc:
Conducted as and when needed, often in response to a specific event or situation that has the potential to introduce new risks or change the nature of existing risks
#### Recurring Risk:
Conducted at regular intervals, such as annually, quarterly, or monthly
#### One-Time Risk:
Conducted for a specific purpose and are not repeated
#### Continuous Risk:
Ongoing monitoring and evaluation of risks
### Risk Identification
Recognizing potential risks that could negatively impact an organization's ability to operate or achieve its objectives
#### Business Impact Analysis:
Process that involves evaluating the potential effects of disruption to an organization's business functions and processes
#### Recovery Time Objective (RTO):
It represents the maximum acceptable length of time that can elapse before the lack of a business function severely impacts the organization
#### Recovery Point Objective (RPO):
It represents the maximum acceptable amount of data loss measured in time
#### Mean Time to Repair (MTTR):
It represents the average time required to repair a failed component or system
#### Mean Time Between Failures (MTBF):
It represents the average time between failures
### Risk Register (Risk Log)
A document detailing identified risks, including their description, impact likelihood, and mitigation strategies
- Risk description: Entails identifying and providing a detailed description of the risk
- Risk impact: Potential consequences if the risk materializes
- Risk likelihood: Chance of a particular risk occurring
- Risk outcome: Result of a risk, linked to its impact and likelihood
- Risk level: Determined by combining the impact and likelihood
- Cost: Pertains to its financial impact on the project, including potential expenses if it occurs or the cost of risk mitigation
#### Risk Management:
Crucial for projects and businesses, involving the identification and assessment of uncertainties that may impact objectives
#### Risk Tolerance/Risk Acceptance:
Refers to an organization or individual's willingness to deal with uncertainty in pursuit of their goals
#### Risk Appetite:
Signifies an organization's willingness to embrace or retain specific types and levels of risk to fulfill its strategic goals
- Expansionary: Organization is open to taking more risk in the hopes of achieving greater returns
- Conservative: Implies that an organization favors less risk, even if it leads to lower returns
- Neutral: Signifies a balance between risk and return
#### Key Risk Indicators (KRIs):
Essential predictive metrics used by organizations to signal rising risk levels in different parts of the enterprise
#### Risk Owner:
Person or group responsible for managing the risk
### Qualitative Risk Analysis
A method of assessing risks based on their potential impact and the likelihood of their occurrence (low, medium, high)
### Quantitative Risk Analysis
Method of evaluating risk that uses numerical measurements
#### Single Loss Expectancy (SLE):
Monetary value expected to be lost in a single event
#### Annualized Rate of Occurrence (ARO):
Estimated frequency with which a threat is expected to occur within a year
#### Annualized Loss Expectancy (ALE):
Expected loss from a risk (SLE x ARO)
#### Exposure Factor (EF):
Proportion of an asset that is lost in an event
### Risk Management Strategies
#### Risk Transference (Risk Sharing):
Involves shifting the risk from the organization to another party
##### Contract Indemnity Clause:
A contractual agreement where one party agrees to cover the other's harm, liability, or loss stemming from the contract
#### Risk Acceptance:
Recognizing a risk and choosing to address it when it arises
##### Exemption:
Provision that grants an exception from a specific rule or requirement
##### Exception:
Provision that permits a party to bypass a rule or requirement in certain situations
#### Risk Avoidance:
Strategy of altering plans or approaches to completely eliminate a specific risk
#### Risk Mitigation:
Implementing measures to decrease the likelihood or impact of a risk
### Risk Monitoring and Reporting
#### Risk Monitoring:
Involves continuously tracking identified risks, assessing new risks, executing response plans, and evaluating their effectiveness during a project's lifecycle
#### Risk Reporting:
Process of communicating information about risk management activities
___
# Third-Party Vendor Risks
Potential security and operational challenges introduced by external entities (vendors, suppliers, or service providers)
### Supply Chain Risks
#### Managed Service Providers (MSPs):
Organizations that provide a range of technology services and support to businesses and other clients
### Supply Chan Attacks
Attack that involves targeting a weaker link in the supply chain to gain access to a primary target
#### CHIPS Act:
U.S. federal statute that provides roughly $280 billion in new funding to boost research and manufacturing of semiconductors inside the United States
#### What Can You Do?
- Vendor due diligence
- Regular monitoring and audits
- Education and collaboration
- Incorporating contractual safeguards
### Vendor Assessment
Process that organizations implement to evaluate the security, reliability, and performance of external entities
#### Penetration Testing:
Simulated cyberattack against the supplier's system to check for exploitable vulnerabilities
#### Internal Audit:
Vendor's self-assessment where they evaluate their own practices against industry standards or organizational requirements
#### Independent Assessment:
Evaluation conducted by third-party entities that have no stake in the organization's or vendor's operations
#### Supply Chain Analysis:
Used to dive deep into a vendor's entire supply chain and assess the security and reliability of each link
### Vendor Selection and Monitoring
Using due diligence to go beyond surface-level credentials
- Financial stability
- Operational history
- Client testimonials
- On-the-ground practices
#### Vendor Questionnaires:
Comprehensive documents that potential vendors fill out to offer insights into the operations, capabilities, and compliance
#### Monitoring:
Mechanism to ensure that the chosen vendor still aligns with the organizational needs and standards
### Contracts and Agreements
#### Basic Contract:
Versatile tool that formally establishes a relationship between two parties
#### Service-Level Agreement (SLA):
The standard of service a client can expect from a provider
#### Memorandum of Agreement (MOA):
Formal and outlines the specific responsibilities and roles of the involved parties
#### Memorandum of Understanding (MOU):
Less binding and more of a declaration of mutual intent
#### Master Service Agreement (MSA):
Blanket agreement that covers the general terms of engagement between parties across multiple transactions
#### Statement of Work (SOW):
Used to specify details for a particular project
#### Non-Disclosure Agreement (NDA):
Commitment to privacy that ensures that any sensitive information shared during negotiations remains confidential between both parties
#### Business Partnership Agreement (BPA):
Document that goes a step beyond the basic contract when two entities decide to pool their resources for mutual benefit
___
# Governance and Compliance
### Governance
Strategic leadership, structures, and processes that ensures an organization's IT infrastructure aligns with its business objectives
#### Monitoring:
Regularly reviewing and assessing the effectiveness of the governance framework
### Governance Structures
#### Boards:
A board of directors is a group of individuals elected by shareholders to oversee the management of an organization
#### Committees:
Subgroups of a board of directors, each with a specific focus
#### Government Entities:
They establish laws and regulations that organizations must comply with
#### Centralized Structures:
Decision-making authority is concentrated at the top levels of management
#### Decentralized Structures:
Distributes decision-making authority throughout the organization
### Policies
#### Acceptable Use (APUP):
A document that outlines the do's and don'ts for users when interacting with an organization's IT systems and resources
#### Information Security:
Outline how an organization protects its information assets from threats, both internal and external
#### Business Continuity:
Focuses on how an organization will continue its critical operations during and after a disruption
#### Disaster Recovery:
Focuses specifically on how an organization will recover its IT systems and data after a disaster
#### Incident Response:
A plan for handling security incidents
#### SDLC:
Guides how software is developed within an organization
#### Change Management:
Aims to ensure that changes are implemented in a controlled and coordinated manner, minimizing the risk of disruptions
### Standards
Provide a framework for implementing security measures, ensuring that all aspects of an organization's security posture are addressed
#### Access Control Standards:
Determine who has access to what resource within an organization
- DAC
- MAC
- RBAC
### Procedures
Systematic sequences of actions or steps taken to achieve a specific outcome
#### Change Management:
Systematic approach to dealing with changes within an organization
#### Playbooks:
Checklist of actions to perform to detect and respond to a specific type of incident
### Governance Considerations
#### Regulatory Considerations:
These regulations can cover a wide range of areas, from data protection and privacy to environmental standards and labor laws
#### Legal Considerations:
Closely tied to regulatory considerations, but they also encompass other areas such as contract law, intellectual property, and corporate law
#### Industry Considerations:
The specific standards and practices that are prevalent in a particular industry
### Compliance
#### Compliance Reporting: 
Systematic process of collecting and presenting data to demonstrate adherence to compliance requirements
#### Compliance Monitoring:
The process of regularly reviewing and analyzing an organization's operations to ensure compliance with laws, regulations, and internal policies
#### Attestation:
Formal declaration by a responsible party that the organization's process and controls are compliant
### Non-compliance Consequences
Can lead to:
- Fines
- Sanctions
- Reputational damage
- Loss of license
- Contractual impacts
___
# Asset and Change Management
### Acquisition and Procurement
#### Acquisition:
Process of obtaining goods and services
#### Procurement:
Encompasses the full process of acquiring goods and services, including all preceding steps
### Mobile Asset Deployments
#### Bring Your Own Device:
Permits employees to use personal devices for work
#### Corporate-Owned, Personally Enabled (COPE):
Involves the company providing a mobile device to employees for both work and personal use (company vehicle)
#### Choose Your Own Device (CYOD):
Offers a middle ground between BYOD and COPE by allowing employees to choose devices from a company-approved list
### Asset Management
Refers to the systematic approach to governing and maximizing the value of items an entity is responsible for throughout their lifecycle
#### Assignment/Accounting:
Every organization should designate individuals or groups as owners for each of its assets
#### Classification:
Involves categorizing assets based on criteria like function, value, or other relevant parameters as determined by the organization
#### Monitoring/Tracking:
Ensures proper accountability and optimal use of each asset
#### Enumeration:
Involves identifying and counting assets, especially large organizations or during times of asset procurement or retirement
#### Mobile Device Management (MDM):
Lets organizations securely oversee employee devices, ensuring policy enforcement, software consistency, and data protection
### Asset Disposal and Decommissioning
Special Publication 800-88 commonly referred to as the "Guidelines for Media Sanitization"
- Overwriting: Replacing the existing data on a storage device with random bits of information to ensure that the original data is obscured
- Degaussing: Involves using a machine called degausser to produce a strong magnetic field that can disrupt the magnetic domains on storage devices like hard drives or tapes
- Encryption techniques
#### Certification:
An act of proof that the data or hardware has been securely disposed of
### Change Management
An organization's orchestrated strategy to transition from its existing state to a more desirable future state
#### Change Advisory Board (CAB):
Body of representatives from various parts of an organization that is responsible for evaluation of any proposed changes
#### Change Owner:
An individual or a team that initiates the change request
#### Stakeholder:
A person who has a vested interest in the proposed change
#### Impact Analysis:
An integral part of change management process that involves understanding of change's potential fallout
### Change Management Processes
1. Preparation
2. Vision for Change
3. Implementation
4. Verification
5. Documentation
#### Backout Plan:
Predetermined strategy for restoring systems to their initial state in case a change does not go as expected
#### Standard Operating Procedures (SOP):
A step-by-step instruction that guides the carrying out of a specific task to maintain consistency and efficiency
### Technical Implications of Change
1. Allow and Deny lists
2. Restricted activities
3. Complex applications interplay
4. Dependencies
#### Legacy Application:
Older software or system that is being used and meets the needs of users
### Documenting Changes
- Version control is occurring
- Proper documentation updates are performed
- Maintenance of various associated records is completed
#### Version Control:
Tracks and manages changes in documents and software, enabling collaborative work and reverting to prior versions when needed
___
# Audits and Assessments
### Internal Audits and Assessments
#### Internal Audit:
Systematic evaluation of the effectiveness of internal controls, compliance, and integrity of information systems and processes
- Data protection
- Network security
- Access controls
- Incident response
##### Compliance:
Ensuring that information systems and security practices meet established standards, regulations, and laws
##### Audit Committee:
Group of people responsible for supervising the organization's audit and compliance functions
#### Internal Assessment:
An in-depth analysis to identify and assess potential risks and vulnerabilities in an organization's information systems
- Self-assessment
### Performing an Internal Assessment
#### Minnesota Counties Intergovernmental Trust (MCIT):
Created a checklist to help members to reduce data and cyber security risks by identifying and addressing vulnerabilities
### External Audits and Assessments
#### External Audit:
Systematic evaluation carried out by external entities to assess an organization's information systems and controls
#### External Assessment:
Detailed analysis conducted by independent entities to identify vulnerabilities and risks
##### Regulatory Compliance:
Objective that organizations aim to reach in adherence to applicable laws, policies, and regulations
##### Examination:
Comprehensive security infrastructure inspections that are conducted externally
##### Independent Third-party Audit:
Offers validation of security practices, fostering trust with customers, stakeholders, and regulatory authorities
### Penetration Testing
Simulated cyber attack that helps in the assessment of computer systems for exploitable vulnerabilities
### Reconnaissance in Pentesting
An initial phase where critical information about a target system is gathered to enhance an attack's effectiveness and success
- Known environment: Detailed target infrastructure information from the organization is received prior to the test
- Partially known environment: Involves limited information provided to testers
- Unknown environment: Testers receive minimal to no information
### Performing a Basic Pentest
#### Metasploit:
Multi-purpose computer security and penetration testing framework that encompasses a wide array of powerful tools, enabling the execution of penetration tests
#### Nmap:
Port scanner
### Attestation of Findings
Process that involves the formal validation or confirmation provided by an entity that is used to assert the accuracy and authenticity of specific information
#### Software Attestation:
Involves validating the integrity of software by checking that it hasn't been tampered with or altered maliciously
#### Hardware Attestation:
Involves validating the integrity of hardware components
#### System Attestation:
Involves validating the security posture of a system
___
# Cyber Resilience and Redundancy
### High Availability
The ability of a service to be continuously available by minimizing the downtime to the lowest amount possible
5 9's = 99.999% uptime or 5 min downtime
6 9's = 99.9999% uptime or 31 seconds downtime
#### Load Balancing:
The process of distributing workloads across multiple computing resources
#### Clustering:
The use of multiple computers, multiple storage devices, and redundant network connections that all work together as a single system to provide high levels of availability, reliability, and scalability
#### Redundancy:
The duplication of critical components or functions of a system with the intention of increasing the reliability of the system
### Data Redundancy
#### Redundant Array of Independent Disks (RAID):
Combines multiple physical storage devices into a recognized single logical storage device
##### RAID 0:
Provides data **striping** across multiple disks to increase performance
##### RAID 1:
**Mirrors** data for redundancy across two drives or SSDs
##### RAID 5:
**Stripes data with parity**, using at least three storage devices
##### RAID 6:
Uses data **striping** across multiple devices with **two pieces of parity** data
##### RAID 10:
Combines RAID 1 and RAID 0, features **mirrored arrays in a striped** setup
#### Failure-resistant:
Use of redundant storage to withstand hardware malfunctions without data loss
#### Fault-tolerant:
Use of RAID 1, 5, 6, and 10 for uninterrupted operation during hardware failures
#### Disaster-tolerant:
Protects data from catastrophic events
### Capacity Planning
Crucial strategic planning to meet future demands cost-effectively
- People
- Technology
- Infrastructure
- Processes
### Powering Data Centers
#### Conditions: 
- Surges: A small and unexpected increase in the amount of voltage that is being provided
- Spikes: A short transient voltage that is usually caused by a short circuit, a tripped circuit breaker, a power outage, or a lightning strike
- Sags: A small and unexpected decrease in the amount of voltage that is being provided
- Under voltage events: Occurs when the voltage is reduced to lower levels and usually occur for a longer period of time
- Full power loss events: Occurs when there is a total loss of power for a given period of time
#### Counter-measures:
- Line conditioners: Used to overcome any minor fluctuations in the power being received by the given system
- UPS: A device that provides emergency power to a system when the normal input power source has failed
- Generators: Machine that converts mechanical energy into electrical energy for use in an external circuit throughout the process of electromagnetic induction
- Power distribution centers (PDCs): Acts as a central hub where power is received and then distributed to all systems in the data center
### Data Backups
The process of creating duplicate copies of digital information to protect against data loss, corruption, or unavailability
#### Replication:
Making real-time, or near-real-time copies of the data
#### Journaling:
Maintaining a meticulous record of every change made to an organization's data over time
### Continuity of Operations Plan
Ensures an organization's ability to recover from disruptive events or disasters
#### Business Continuity Plan (BCP):
Addresses responses to disruptive events/**incidents**
#### Disaster Recovery Plan (DRP):
Considered as a subset of BC Plan, it focuses on how to resume operations swiftly after a **disaster**
### Redundant Site Considerations
Alternative sites for backup in case the primary location encounters a failure or interruption
#### Hot Site:
A fully equipped backup facility ready to swiftly take over in case of a primary site failure or disruption
#### Warm Site:
A partially equipped backup site that can become operational within days of a primary site disruption
#### Cold Site:
A site with no immediate equipment or infrastructure but can be transformed into a functional backup facility
#### Mobile Site:
A versatile site that utilizes independent and portable units like trailers or tents to deliver recovery capabilities
#### Virtual Site:
Utilizes cloud-based environments and offers highly flexible approach to redundancy
### Resilience and Recovery Testing
#### Resilience Testing:
Assesses the system's capacity to endure and adjust to disruptive occurrences
#### Recovery Testing:
Evaluates the system's ability to return to regular functioning following a disruptive incident
#### Testing:
- Tabletop exercise: A simulated discussion to improve crisis readiness without deploying resources
- Failover test: Verifies seamless system transition to a backup for uninterrupted functionality during disasters
- Simulation: Computer-generated representation of real-world scenarios
- Parallel processing: Replicates data and processes onto a secondary system, running both in parallel
___
# Security Architecture
### On-premise versus the Cloud
#### Responsibility Matrix:
Outlines the division of responsibilities between the cloud service provider and the customer
### Cloud Security
#### Vulnerabilities:
- Shared physical server vulnerabilities
- Inadequate virtual environment security
- User access management
- Lack of up-to-date security measures
- Single point of failure
- Weak authentication and encryption practices
- Unclear policies and data remnants (left behind after deletion)
### Virtualization and Containerization
#### Virtualization:
Technology that allows for the emulation of servers
#### Containerization:
Lightweight alternative to full machine virtualization
- Docker
- Kubernetes
- Red Hat OpenShift
#### Hypervisor Types:
- Type 1: Known as a bare metal or native hypervisor, it runs directly on the host hardware and functions similarly to an operating system (Hyper-V, XenServer, ESXi, vSphere) and is more efficient
- Type 2: Operates within a standard operating system, such as Windows, Mac, or Linux
#### Vulnerabilities:
- VM escape
- Privilege elevation
- Live VM migration: When a VM needs to move from one physical host to another
- Resource reuse
###  Serverless
Model where the responsibility of managing servers, databases, and some application logic is shifted away from developers
- Beware of vendor lock-in
### Microservices
A software architecture where large applications are broken down into smaller and independent services
- Netflix (recommendation system, user sign up, etc.)
### Network Infrastructure
#### Physical Separation/Air Gapping:
Isolation of a network by removing any direct or indirect connections from other networks
- Military HQ
- Water facilities
#### Logical Separation:
Creates boundaries within a network, restricting access to certain areas
### Software-Defined Network (SDN)
Enables efficient network configuration to improve performance and monitoring
#### Data Plane:
Also called the forwarding plane that is responsible for handling packets and makes decisions based on protocols
#### Control Plane:
The brain of the network that decides where traffic is sent and is centralized in SDN
#### Application Plane:
The plane where all network applications interacting with the SDN controller reside
### Infrastructure as Code (IaC)
A method in which IT infrastructures are defined in code files that can be versioned, tested, and audited
- Speed and efficiency
- Consistency and standardization
- Scalability
- Cost savings
- Auditability and compliance
#### Snowflake System:
A configuration that lacks consistency that might introduce risks, so it has to be eliminated
#### Idempotence:
The ability of an operation to produce the same results as many times as it is executed
### Centralized vs Decentralized Architectures
#### Centralized:
All the computing functions are coordinated and managed from a single location or authority
- **Efficiency and control**
- **Consistency**
- **Cost and effectiveness**
- Single point of failure
- Scalability issues
- Security risks
#### Decentralized:
Computing functions are distributed across multiple systems or locations
- **Resiliency**
- **Scalability**
- **Flexibility**
- Security risks
- Management challenges
- Data inconsistency
### Internet of Things (IoT)
Refers to the network of physical items with embedded systems that enables connection and data exchange
#### Hub:
The central point connection all IoT devices and sends commands to them
### Industrial Control Systems (ICS) and Supervisory Control and Data Acquisition (SCADA)
#### ICS:
Control systems used to monitor and control industrial processes ranging from simple systems to complex systems
- Distributed Control Systems (DCS)
-  Programmable Logic Controllers (PLCs)
#### SCADA:
A type of ICS used to monitor and control geographically dispersed industrial processes
#### Counter-measures to Vulnerabilities:
- Strong access controls
- Regular updates
- Firewall and IDS
- Regular security audits
- Employee training
### Embedded Systems
Specialized computing component designed to perform dedicated functions within a larger structure
#### Real-Time Operating System (RTOS):
Ensures data processing in real-time and is crucial for time-sensitive applications
#### Wrappers:
Show only the entry and exit points of the data when travelling between networks
___
# -Security Infrastructure
### Ports and Protocols
#### Port:
Logical communication endpoint that exists on a computer or server
##### Port 21 (TCP)
- FTP: Transfer files
##### Port 22 (TCP)
- SSH, SCP, and SFTP: Secure remote terminal access and file transfer
##### Port 23 (TCP)
- Telnet: Provides insecure remote control of another machine using a text-based environment
##### Port 25 (TCP)
- SMTP: Provides the ability to send emails over the network
##### Port 53 (TCP and UDP)
- DNS: Translates domain names into IP addresses
##### Port 69 (UDP)
- TFTP: Used as a lightweight file transfer method for sending configuration files or network booting of an OS
##### Port 80 (TCP)
- HTTP: Insecure web browsing
##### Port 88 (UDP)
- Kerberos: Network authentication protocol
##### Port 110 (TCP)
- POP3: Responsible for retrieving email from a server
##### Port 119 (TCP)
- NNTP: Used for accessing newsgroups
##### Port 135 (TCP and UDP)
- RPC: Facilitates communication between different system processes
##### Ports 137, 138, 139 (TCP and UDP)
- NetBIOS: Networking protocol suite
##### Port 143 (TCP)
- IMAP: Allows access to email messages on a server
##### Port 161 (UDP)
- SNMP: Manages network devices
##### Port 162 (UDP)
- SNMP Trap: Responsible for sending SNMP trap messages
##### Port 389 (TCP)
- LDAP: Facilitates directory services
##### Port 443 (TCP)
- HTTPS: Secure web communication
##### Port 445 (TCP)
- SMB: Used for file and printer sharing over a network
##### Port 465, 587 (TCP)
- SMTPS: Secure SMTP
##### Port 514 (UDP)
- Syslog: Used for sending log messages
##### Port 636 (TCP)
- LDAPS: LDAP over SSL/TLS
##### Port 993 (TCP)
- IMAPS: Secure email retrieval
##### Port 995 (TCP)
- POP3S: Secure email retrieval
##### Port 1433 (TCP)
- Microsoft SQL: Facilitate communication with Microsoft SQL Server
##### Port 1645, 1646 (TCP)
- Radius TCP: Remote authentication, authorization, and accounting
##### Port 1812, 1813 (UDP)
- Radius TCP: Authentication and accounting as defined by the IETF
##### Port 3389 (TCP)
- RDP: Enables remote desktop access
##### Port 6514 (TCP)
- Syslog TLS: Secure syslog that uses SSL/TLS to encrypt the IP packets using a certificate before sending them across the IP network to the syslog collector
#### Inbound Port:
Logical communication opening on a server that is listening for a connection from a client
#### Outbound Port:
Logical communication opening created on a client in order to call out to a server that is listening for a connection
### Firewalls
Safeguards networks by monitoring and controlling traffic based on predefined security rules
#### Screened Subnet (Dual-homed Host):
Acts as a security barrier between external untrusted networks and internal trusted networks, using a protected host with security measures like a packet-filtering firewall
#### Packet Filtering:
Checks packet headers for traffic allowance based on IP addresses and port numbers
#### Stateful:
Monitors all inbound and outbound network connections and requests
#### Proxy:
Acts as an intermediary between internal and external connections, making connections on behalf  of other endpoints
##### Circuit Level:
Like a SOCKS firewall, operates at the Layer 5 of the OSI model
##### Application Level:
Conducts various proxy functions for each type of application at the Layer 7 of the OSI model
#### Kernel Proxy:
Has minimal impact on network performance while thoroughly inspecting packets across all layers
#### Next-Generation Firewall (NGFW):
Aims to address the limitations of traditional firewalls by being more aware of applications and their behaviors
#### Unified Threat Management Firewall (UTM):
Provides the ability to conduct multiple security functions in a single appliance
#### Web Application Firewall (WAF):
Focuses on the inspection of the HTTP traffic
### IDS and IPS
#### IDS:
Detects, logs, reports
- NIDS
- HIDS
- WIDS (Wireless)
##### Signature-based IDS:
Analyzes traffic based on defined signatures and can only recognize attacks based on previously identified attacks in its database
- Pattern-matching: NIDS, WIDS
- Stateful-matching: HIDS
##### Anomaly-based/Behavioral-based IDS:
Analyzes traffic and compares it to a normal baseline of traffic to determine whether a threat is occurring
- Statistical
- Protocol
- Traffic
- Rule/Heuristic
- Application-based
#### IPS:
Detects, logs, takes action
### Network Appliances
Dedicated hardware device with pre-installed software that is designed to provide specific networking services
#### Load Balancers:
Crucial component in any high-availability network or system that is designed to distribute network or application traffic across multiple servers
#### Proxy Servers:
Intermediary between a client and a server to provide various functions like content cracking, request filtering, and login management
#### Sensors:
Designed to monitor, detect, and analyze traffic and data flow access a network in order to identify any unusual activities, potential security breaches, or performance issues
#### Jump Servers:
Dedicated gateway used by system administrators to securely access devices located in different security zones within the network
### Port Security
Common security feature found on network switches that allows administrators to restrict which devices can connect to a specific port based on the network interface card's MAC address
#### Content Addressable Memory (CAM) Table:
Used to store information about the MAC addresses that are available on any given port of the switch
#### Persistent (Sticky) MAC Learning:
Feature in network port security where the switch automatically learns and associates MAC addresses with specific interfaces
#### 802.1x Protocol:
Standardized framework that is used for port-based authentication for both wired and wireless networks
#### EAP-MD5:
Variant that utilizes simple passwords and the challenge handshake authentication process to provide remote access authentication
#### EAP-TLS:
Form of EAP that uses public key infrastructure with a digital certificate being installed on both the client and the server as the method of authentication
#### EAP-TTLS:
Variant that requires a digital certificate on the server, but not on the client
#### EAP-FAST:
Variant that uses a protected access credential, instead of a certificate, to establish mutual authentication between devices
#### PEAP:
Variant that supports mutual authentication by using server certificates and the Microsoft Active Directory databases for it to authenticate a password from the client
#### LEAP:
Variant of EAP that only works on Cisco-based devices
### Securing Network Communications
#### VPN:
Extends a private network over a public one, enabling users to securely send and receive data
#### TLS:
A protocol that provides cryptographic security for secure connections and is used for secure web browsing and data transfer
#### IPSec:
A protocol suite for secure communication through authentication and data encryption in IP networks
###### Authentication Header (AH):
Offers connectionless data integrity and data origin authentication for IP datagrams using cryptographic hash as identification information
###### Encapsulating Security Payload (ESP):
Employed for providing authentication, integrity, replay protection, and data confidentiality by encrypting the packet's payload
##### Request to start Internet Key Exchange (IKE):
PC1 initiates traffic to PC2, triggering IPSec tunnel creation by RTR1
##### IKE Phase 1:
RTR1 and RTR2 negotiate security associations for the IPSec IKE Phase 1 (ISAKMP) tunnel
##### IKE Phase 2:
IKE Phase 2 establishes a tunnel within the tunnel
##### Data Transfer:
Data transfer between PC1 and PC2 takes place securely
###### Transport Mode:
Employs the original IP header, ideal for client-to-site VPNs, and is advantageous when dealing with MTU (Maximum Transmission Unit is set only at 1500 bytes and may cause fragmentation and VPN problems) constraints
###### Tunneling Mode:
Employed for site-to-site VPNs and adds an extra header that can increase packet size and exceed the MTU
##### Tunnel Termination:
Tunnel termination, including the deletion of IPSec security associations
### SD-WAN and SASE
#### Software-Defined Wide Area Network (SD-WAN):
Virtualized approach to managing and optimizing wide area network connections to efficiently route traffic between remote sites, data centers, and cloud environments
#### Secure Access Service Edge (SASE):
Used to consolidate numerous networking and security functions into a single cloud-native service to ensure that secure and access for end-users can be achieved
### Infrastructure Considerations
#### Security Zone:
Distinct segment within a network, often created by logically isolating the segment using a firewall or other security device
#### Screened Subnet:
Hosts public-facing services such as web servers, email servers, and DNS servers and safeguards against security breaches by preventing attackers from gaining direct access to the sensitive core internal network
#### Attack Surface of a Network:
Refers to all the points where an unauthorized user can try to enter data to or extract data from an environment

___
# Identity and Access Management (IAM) Solutions
### Identity and Access Management (IAM)
Systems and processes used to manage access to information in an organization to ensure that the right individuals have access to the right resources at the right times for the right reasons
- Identification
- Authentication
- Authorization
- Accounting
#### Provisioning: 
Process of creating new user accounts, assigning them appropriate permissions, and providing users with access to systems
#### Deprovisioning:
Process of removing an individual's access rights when the rights are no longer required
#### Identity Proofing:
Process of verifying the identity of a user before the account is created
#### Interoperability:
The ability of different systems, devices, and applications to work together and share information
#### Attestation:
Process of validating that user accounts and access rights are correct and up-to-date
### MFA
Security system that requires more than one method of authentication from independent categories of credentials to verify the user's identity
#### Knowledge-based Factor:
Knowledge-based information that the user must provide to authenticate their identity
#### Possession-based Factor:
Something the user physically possess like a smart card, a hardware token like a key fob, or a software token used with a smartphone
#### Inherence-based Factor:
Involves biometric characteristics that are unique to individuals, including fingerprints, facial recognition, voice recognition, or iris scans
#### Behavior-based Factor:
Recognizing patterns that are typically associated with a user, such as their keystroke patterns, mouse movement, or even the way a user walks down the hallway
#### Location-based Factor:
Involves determining a user's location to help authenticate them
### Password Security
Measures the password's ability to resist guessing and brute-force attacks
### Password Attacks
#### Brute Force Attacks:
Trying every possible combination until a correct password is found
#### Dictionary Attacks:
Using a list of commonly used passwords
#### Spraying Attacks:
Trying a small number of commonly used passwords against a large number of usernames or accounts
#### Hybrid Attacks:
Blends brute force and dictionary techniques by using common passwords with variations, such as adding numbers or special characters
### Single Sign-On (SSO)
Authentication process that allows a user to access multiple applications or websites by logging in only once with a single set of credentials
#### Identity Provider (IdP):
System that creates, maintains, and manages identity information for principals while providing authentication services to relying applications within a federation or distributed network
#### Lightweight Directory Access Protocol (LDAP):
Used to access and maintain distributed directory information services over an Internet protocol network
#### Open Authorization (OAuth):
Open standard for token-based authentication and authorization that allows an individual's account information to be used by third-party services without exposing the user's password
#### Security Assertion Markup Language (SAML):
A standard for logging users into applications based on their sessions in another context
### Federation
Process that allows for the linking of electronic identities and attributes to store information across multiple distinct identity management systems
### Privileged Access Management (PAM)
Solution that helps organizations restrict and monitor privileged access within an IT environment
### Access Control Models
#### Mandatory Access Control (MAC):
Employs security labels to authorize user access to specific resources
#### Discretionary Access Control (DAC):
Resource's owner determines which users can access each resource
#### Role-based Access Control (RBAC):
Assigns users to roles and uses these roles to grant permissions to resources
#### Rule-based Access Control (RBAC):
Enables administrators to apply security policies to all users
#### Attribute-based Access Control (ABAC):
Used object characteristics for access control decisions
### Assigning Permissions
#### User Account Control (UAC):
A mechanism designed to ensure that actions requiring administrative rights are explicitly authorized by the user
___
# Vulnerabilities and Attacks
### Hardware Vulnerabilities
Security flaws or weaknesses inherent in a device's physical components or design that can be exploited to compromise the integrity, confidentiality, or availability of the system and its data
#### Firmware:
Specialized form of software stored on a device, like a router or a thermostat, that provides low-level control for the device's specific hardware
#### Hardware Misconfiguration:
Occurs when a device's settings, parameters, or options are not optimally set up, and this can cause vulnerabilities to exist, a decrease in performance, or unintended behavior of devices or systems
#### Counter-measures:
- Hardening: Tightening security of a system
- Patching
- Configuration enforcement
- Decommissioning
- Isolation
- Segmentation
### Bluetooth Vulnerabilities and Attacks
- Insecure Pairing
- Device Spoofing
- On-path Attacks: Exploits BT protocol vulnerabilities to intercept and later communications between devices
#### Attacks:
- Bluejacking: Unsolicited messages
- Bluesnarfing: Unauthorized access to acquire contacts, call logs, texts
- Bluebuggung: Takes Bluesnarfing a step further by taking control of functions to make calls, send texts, access internet
- Bluesmack: DoS
- Blueborne: Infects other devices on network
### Mobile Vulnerabilities and Attacks
#### Sideloading:
The practice of installing applications on a device from unofficial sources which actually bypasses the device's default app store
#### Jailbreaking/Rooting:
Process that gives users escalated privileges on the devices and allows users to circumvent the built-in security measures provided by the devices
#### Mobile Device Management (MDM) Solution:
Used to conduct patching of the devices by pushing any necessary updates to the devices to ensure that they are always equipped with the latest security patches
### Zero-day Vulnerabilities
Any vulnerability that's discovered or exploited before the vendor can issue a patch for it
### Operating System Vulnerabilities
#### Data Exfiltration:
Unauthorized data transfers from within an organization to an external location
#### Malicious Updates:
Occur when an attacker has been able to craft a malicious update to a well-known and trusted program in order to compromise the systems of the program's end users
### SQL and XML Injections
#### SQL/XML Injection Counter-measures:
- User input validation
- Sanitize data
#### XML Bomb (Billion Laughs Attack):
XML encodes entities that expand to exponential sizes, consuming memory on the host and potentially crashing it
#### XML External Entity (XXE):
An attack that embeds a request for a local resource
### XSS and XSRF
#### Cross-Site Scripting (XSS):
Injects a malicious script into a trusted site to compromise the site's visitors
#### Non-Persistent XSS:
This type of attack only occurs when it's launched and happens once
#### Persistent XSS:
Allows an attacker to insert code into the backend database used by that trusted website
#### Document Object Model (DOM) XSS:
Exploits the client's web browser using client-side scripts to modify the content and layout of the web page
#### Session Hijacking:
Type of spoofing attack where the attacker disconnects a host and then replaces it with his or her own machine by spoofing the original host IP
#### Session Prediction:
Type of spoofing attack where the attacker attempts to predict the session token in order to hijack the session
#### Cross-Site Request Forgery (XSRF):
Malicious script is used to exploit a session started on another site within the same web browser
### Buffer Overflow
Occurs when data exceeds allocated memory, potentially enabling unauthorized access or code execution
#### Address Space Layout Randomization (ASLR):
A security measure that randomizes memory addresses, making buffer overflow attacks harder for attackers
### Race Conditions
Software vulnerability where the outcome depends on the timing of events not matching the developer's intended order
#### Time-of-Check (TOC):
Type of race condition where an attacker can alter a system resource after an application checks its state but before the operation is performed
#### Time-of-Use (TOU):
Type of race condition that occurs when an attacker can change the state of a system resource between the time it is checked and the time it is used
#### Time-of-Evaluation (TOE):
Type of race condition that involves the manipulation of data or resources during the time window when a system is making a decision or evaluation
#### Mutex:
Mutually exclusive flag that acts as a gatekeeper to a section of code so that only one thread can be processed at a time
#### Deadlock:
Occurs when a lock remains in place because the process it's waiting for is terminated, crashes, or doesn't finish properly despite the processing being complete
___
# -Malicious Activity
### Distributed Denial of Service (DDoS)
Used to describe an attack that attempts to make a computer or server's resources unavailable
#### Flood Attack:
Specialized type of DoS which attempts to send more packets to a single server or host than it can handle
#### Permanent Denial of Service (PDoS):
An attack which exploits a security flaw by reflashing a firmware, permanently breaking networking device
#### DNS Amplification Attack:
Specialized DDoS that allows an attacker to initiate DNS requests from a spoof IP address to flood a website
### Domain Name System (DNS) Attacks
#### DNS Cache Poisoning:
Involves corrupting the DNS cache data of a DNS resolver with false information
#### DNS Amplification Attack:
The attacker overloads a target system with DNS response traffic by exploiting the DNS resolution process
#### DNS Tunneling:
Uses DNS protocol over port 53 to encase non-DNS traffic, trying to evade firewall rules for command control or data exfiltration
#### Domain Hijacking:
Altering a domain name's registration without the original registrant's consent
#### DNZ Zone Transfer Attack:
The attacker mimics an authorized system to request and obtain the entire DNS zone data for a domain
### Directory Traversal Attack
A type of injection attack that allows access to commands, files, and directories, either connected to web document root directory or not
#### File Inclusion:
Allows an attacker to either download files from an arbitrary location or upload an executable or script file to open a backdoor
### Execution and Escalation Attack
- Arbitrary Code Execution: A vulnerability that allows an attacker to run a code or module that exploits a vulnerability
- Remote Code Execution
- Privilege Esc
- Rootkits: A class of malware that modifies system files, often at the kernel level, to conceal its presence
### Replay Attacks
Type of network-based attack that involves maliciously repeating or delaying valid data transmissions
### Session Hijacking
A type of spoofing attack where the host is disconnected and replaced by the attacker
#### Session Management:
A fundamental security component that enables web applications to identify a user
#### Cookie Poisoning:
Modifying the contents of a cookie to be sent to a client's browser and exploit the vulnerabilities in an application
### On-Path Attacks
An attack where the penetration tester puts the workstation logically between two hosts during the communication
### Injection Attacks
- LDAP Injection
- Command Injection
### Indicators of Compromise (IoC)
Data pieces that detect potential malicious activity on a network or system
- Account lockouts
- Concurrent session usage
- Blocked content
- Impossible travel
- Resource consumption
- Resource inaccessibility
- Out-of-cycle logging
- Articles or documents on security breach
- Missing logs
___
# Hardening
### Changing Default Configurations
- Default passwords
- Unneeded ports and protocols
- Extra open ports
### Restricting Applications
- Least functionality
- Secure baseline image: A standardized workstation setup
	- Allowlisting
	- Blocklisting
### Trusted Operating Systems (TOS)
Designed to provide a secure computing environment by enforcing stringent security policies that usually rely on mandatory access controls
### Updates and Patches
- Hotfix
- Updates
- Service Pack
### Patch Management
Planning, testing, implementing, and auditing of software patches
### Group Policies
Set of rules or policies that can be applied to a set of users or computer accounts within an operating system
#### Security Template:
A group of policies that can be loaded through one procedure
#### Baselining:
Process of measuring changes in the network, hardware, or software environment
### SELinux
Default context-based permission scheme that's included inside of CentOS and Red Hat Enterprise Linux
### Data Encryption Levels
Process of converting data into a secret code to prevent unauthorized access
- Full-disk
- Partition
- Volume
- Record-level
- Database
### Secure Baselines
Standard security configuration applied to guarantee minimum security for a system, network, or application
___
# -Security Techniques
### Wireless Infrastructure Security
#### Extended Service Set (ESS) Configuration:
Involves multiple wireless access points working together to create a unified and extended coverage area for users in a large building or facility
### Wireless Security Settings
#### Wired Equivalent Privacy (WEP):
Outdated 1999 wireless security standard meant to match wired LAN security for wireless networks
#### Wi-Fi Protected Access (WPA):
Introduced in 2003 as a temporary improvement over WWEP while the more robust IEEE 802.11i standard was in development
#### Wi-Fi Protected Access 2 (WPA2):
Improved data protection and network access control by addressing weaknesses in WPA version
#### Wi-Fi Protected Access 3 (WPA3):
Latest version using AES encryption and introducing new features like SAE, Enhanced Open, updated cryptographic protocols, and management protection frames
#### Simultaneous Authentication of Equals (SAE):
Enhances security by offering a key establishment protocol to guard against offline dictionary attacks
#### Enhanced Open/Opportunistic Wireless Encryption (OWE):
Major advancement in wireless security, especially for networks using open authentication
#### Cryptographic Protocol:
Uses a newer variant of AES known as the AES GCMP
#### Galois Counter Mode Protocol (GCMP):
Supports 128-bit AES for personal networks and 192-bit AES for enterprise networks with WPA3
#### Authentication Authorization and Accounting (AAA) Protocol:
Plays a vital role in network security by centralizing user authentication to permit only authorized users to access network resources
##### Remote Authentication Dial-In User Service (RADIUS):
Client/server protocol offering AAA services for network users
##### Terminal Access Controller Access-Control System Plus (TACACS+):
Separates the functions of AAA to allow for a more granular control over processes
#### Extensible Authentication Protocol (EAP):
Authentication framework that supports multiple authentication methods
### Application Security
Critical aspect of software development that focuses on building applications that are secure by design
#### Static Code Analysis (SAST):
A method of debugging an application by reviewing and examining its source code before the program is ever run
#### Dynamic Code Analysis:
Testing method that analyzes an application while it's running
##### Fuzzing:
Finds software flaws by bombarding it with random data to trigger crashes and security vulnerabilities
##### Stress Testing:
Type of software testing that evaluates the stability and reliability of a system under extreme conditions
#### Code Signing:
Technique used to confirm the identity of the software author and guarantee that the code has not been altered or corrupted since it was signed
#### Sandboxing:
Security mechanism that is used to isolate running programs by limiting the resources they can access and the changes they can make to a system
### Network Access Control (NAC)
Scans devices for their security status before granting network access, safeguarding against both known and unknown devices
##### Persistent Agent:
A software installed on a device requesting network access
##### Non-Persistent Agent:
Users connect to Wi-Fi, access a web portal, and click a link for login in these solutions
### Web and DNS Filtering
#### Web Filtering:
Technique used to restrict or control the content a user can access on the Internet
- Agent-based: Installing a small piece of software on each device that will require web filtering
- Centralized proxies: Server that acts as an intermediary between an organization's end users and the Internet
- URL scanning
- Content categorization
- Block rules
- Reputation-based: Blocking or allowing websites based on their reputation score
#### DNS Filtering:
Technique used to block access to certain websites by preventing the translation of specific domain names to their corresponding IP addresses
### Email Security
#### Domain Keys Identified Mail (DKIM):
Allows the receiver to check if the email was actually sent by the domain it claims to be sent from and if the content was tampered with during transit
#### Sender Policy Framework (SPF):
Email authentication method designed to prevent forging sender addresses during email delivery
#### Domain-based Message Authentication, Reporting, & Conformance (DMARC):
An email-validation system designed to detect and prevent email spoofing
### Endpoint Detection and Response
Category of security tools that monitor endpoint and network events and record the information in a central database
#### File Integrity Monitoring (FIM):
Used to validate the integrity of operating system and application software files using a verification method between the current file state and a known, good baseline
#### Extended Detection and Response (XDR):
Security strategy that integrates multiple protection technologies into a single platform to improve detection accuracy and simplify the incident response process
### User Behavior Analytics
Deploys big data and machine learning to analyze user behaviors for detecting security threats
___
# Vulnerability Management
### Identifying Vulnerabilities
Systematic practice of spotting and categorizing weaknesses in a system, network, or application that could potentially be exploited
### Vulnerability Response and Remediation
Strategies that identify, assess, and address vulnerabilities in a system or network to strengthen an organization's security posture
### Validating Vulnerability Remediation
- Rescans
- Audits
- Verification
### Vulnerability Reporting
Process of documenting and communicating details about security weaknesses identified in software or systems to the individuals or organizations responsible for addressing the issue
___
# -Alerting and Monitoring
### Monitoring Resources
#### System Monitoring:
Observation of computer system, including the utilization and consumption of its resources
### Alerting and Monitoring Activities
#### Log Aggregation:
Process of collecting and consolidating log data from various sources into a centralized location
### Simple Network Management Protocol (SNMP)
Internet protocol for collecting and organizing information about managed devices on IP networks and for modifying that information to change device behavior
#### Management Information Base (MIB):
Used to describe the structure of the management data of a device subsystem using a hierarchical namespace containing object identifiers
### Security Information and Event Management (SIEM)
Solution that provides real-time or near-real-time analysis of security alerts that are generated by network hardware and applications
### Security Content Automation and Protocol (SCAP)
Open standards that automate vulnerability management, measurement, and policy compliance for systems in an organization
#### Open Vulnerability and Assessment Language (OVAL):
XML schema for describing system security states and querying vulnerability reports and information
#### Extensible Configuration Checklist Description Format (XCCDF):
XML schema for developing and auditing best-practice configuration checklists and rules
#### Asset Reporting Format (ARF):
XML schema for expressing information about assets and the relationships between assets and reports
#### Common Configuration Enumeration (CCE):
Scheme for provisioning secure configuration checks across multiple checks
#### Common Platform Enumeration (CPE):
Scheme for identifying hardware devices, operating systems, and applications
#### Common Vulnerability Scoring System (CVSS):
Used to provide a numerical score to reflect the severity of a given vulnerability
### NetFlow and Flow Analysis
#### Full Packet Capture (FPC):
Captures the entire packet, including the header and the payload for all traffic entering and leaving a network
#### NetFlow:
A Cisco-developed means of reporting network flow into a structured database
#### IP Flow Information Export (IPFIX):
Defines traffic flow based on shared packet characteristics
#### Zeek:
Passively monitors a network like a sniffer, but only logs full packet capture data of potential interest
#### Multi Router Traffic Grapher (MRTG):
Creates graphs showing traffic flows through the network interfaces of routers and switches by pooling the appliances using SNMP
### Single Pane of Glass (SPOG)
A central point of access for all the information, tools, and systems
___
# -Incident Response
### Incident Response Process
- Preparation
- Detection
- Analysis
- Containment
- Eradication
- Recovery
- Post-incident activity/Lessons learned
#### Root Cause Analysis:
Identifies the incident's source and how to prevent it in the future
1. Define/scope the incident
2. Determine the causal relationships that led to the incident
3. Identify an effective solution
4. Implement and track the solutions
### Threat Hunting
Cybersecurity method for finding hidden threats not caught by regular security monitoring
- Advisories and Bulletins
- Intelligence Fusion 
- Threat Data
### Root Cause Analysis
A systematic process to identify the initial source of the incident and how to prevent it from occurring again
### Digital Forensic Procedures
Process of investigating and analyzing digital devices and data to uncover evidence for legal purposes
- Identification
- Collection
- Analysis
- Reporting
#### File Carving:
Focuses on extracting files and data fragments from storage media without relying on the file system
### Data Collection Procedures
1. CPU registers and cache memory
2. RAM
3. HDD/SDD
4. Remote logging
5. Physical configuration and network topology
6. Archival media
___
# Investigating an Incident
### Investigative Data
#### SIEM:
Combination of different data sources into one tool that provides real-time analysis of security alerts generated by applications and network hardware
#### Log File:
A file that records either events that occur in an operating system or other software that runs, or messages between different users of a communication software
#### Syslog/Rsyslog/Syslog-ng:
Variations of syslog which all permit the logging of data from different types of systems in a central repository
#### Sampled Flow (SFlow):
Provides a means for exporting truncated packets, together with interface counters for the purpose of network monitoring
#### Internet Protocol Flow Information Export (IPFIX):
Universal standard of export for Internet Protocol flow information from routers, probes, and other devices that are used by mediation systems, accounting and billing systems, and network management systems to facilitate services
___
# Automation and Orchestration
### When to Automate and Orchestrate
- Complexity
- Cost
- Single points of failure
- Technical debt
- Ongoing supportability
### Automating Security
Involves use of technology to handle repetitive security tasks and maintain consistent defenses
- RBAC
### Integrations and APIs
Process of combining different subsystems or components into one comprehensive system to ensure that they function properly together
#### REST:
Architectural style that uses standard HTTP methods and status codes, uniform resource identifiers, and MIME types
#### SOAP:
Protocol that defines a strict standard with a set structure for the message, usually in XML format
#### Continuous Delivery:
Requires manual deployment to production
#### Continuous Deployment:
Automates the deployment process through to production
___
# Security Awareness
### Avoiding Social Engineering
#### Operational Security (OPSEC):
Stresses data protection against social engineers for business aspects such as routines, project details, and internal procedures
### Policy and Handbooks
#### Policy:
System of rules that guides decisions and actions to ensure compliance with organizational standards and legal ethics
#### Handbook:
Concise booklet offering detailed guidance on organization-specific procedures, guidelines, and best practices for individuals
### Creating a Culture of Security
#### Organizational Change Management (OCM):
Recognizing the human role in security, ensuring staff engagement, and policy adherence
___
