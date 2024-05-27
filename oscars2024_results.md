Affected Platforms: Microsoft Windows
Impacted Users: Microsoft Windows
Impact: Controls victim’s device and collects sensitive information
Severity Level: High

FortiGuard Labs recently uncovered a threat actor employing a malicious PDF file to propagate the banking Trojan CHAVECLOAK. This intricate attack involves the PDF downloading a ZIP file and subsequently utilizing DLL side-loading techniques to execute the final malware. Notably, CHAVECLOAK is specifically designed to target users in Brazil, aiming to steal sensitive information linked to financial activities.

Figure 1 shows the detailed flow of this cyber threat.

Figure 1: Attack flow
Figure 1: Attack flow
In the South American cyberthreat landscape, banking trojans employ a range of tactics, such as phishing emails, malicious attachments, and browser manipulation. Notable examples include Casbaneiro (Metamorfo/Ponteiro), Guildma, Mekotio, and Grandoreiro. These trojans specialize in illicitly obtaining online banking credentials and personal data, posing a significant threat to users in countries like Brazil and Mexico. The CHAVECLOAK's Command and Control (C2) server telemetry is shown in Figure 2. In this blog, we will elaborate on the details of the malware.

Figure 2: Telemetry
Figure 2: Telemetry
Initial Vector PDF
The PDF, shown in Figure 3, claims contain documents related to a contract, with instructions written in Portuguese. It lures its victims to click a button so they can read and sign the attached documents. However, a malicious downloader link is discreetly embedded within the stream object, as shown in Figure 4, which reveals the decoded URL. This URL undergoes processing via the free link shortening service “Goo.su,” ultimately leading to a redirect at hxxps://webattach.mail.yandex.net/message_part_real/NotaFiscalEsdeletronicasufactrub66667kujhdfdjrWEWGFG09t5H6854JHGJUUR[.]zip for downloading the ZIP file. Upon decompression, the file yields the MSI file “NotafiscalGFGJKHKHGUURTURTF345.msi.”

Figure 3: The malicious PDF file
Figure 3: The malicious PDF file
Figure 4: The embedded URL
Figure 4: The embedded URL
MSI Installer
Following the decompression of the MSI installer, we uncovered multiple TXT files related to settings for different languages, a legitimate execution file, and a malicious DLL named “Lightshot.dll.” Notably, the modified date for this DLL file is more recent than that of all the other files in the installer, further emphasizing its unusual nature.

Figure 5: The decompressed MSI file
Figure 5: The decompressed MSI file
Examining the MSI installer reveals its entire configuration, which is written in Portuguese. It executes the file “Lightshot.exe,” extracting and depositing files at “%AppData%\Skillbrains\lightshot\5.5.0.7,” as shown in Figure 6.

The file “Lightshot.exe” then deploys DLL sideloading techniques to activate the execution of the malicious DLL, "Lightshot.dll." This technique lets the legitimate executable load and run the malicious code discreetly, facilitating unauthorized activities like data theft. The actions conducted by “Lightshot.dll” involve covert and harmful operations, including the unauthorized acquisition of sensitive information. DLL sideloading poses a significant security threat by allowing the malware to exploit legitimate processes for nefarious purposes without detection.

Figure 6: The “ActionText” in the MSI file and the extracted folder
Figure 6: The “ActionText” in the MSI file and the extracted folder
Figure 7: Load malicious DLL “Lightshot.dll”
Figure 7: Load malicious DLL “Lightshot.dll”
CHAVECLOAK Banking Trojan “Lightshot.dll”
Initially, the process invokes “GetVolumeInformationW” to gather details about the file system and the associated volume related to the specified root directory. It utilizes the HEX value obtained to generate a log file in “%AppData%[HEX ID]lIG.log.” Following this, it adds a registry value named “Lightshot” to “HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run,” ensuring automatic execution of the “Lightshot.exe” program upon user login. Once logging and persistence are completed, it sends an HTTP request to hxxp://64[.]225[.]32[.]24/shn/inspecionando.php. If geo-checking confirms that the victim is in Brazil, it logs data on the server, accessible through the path “clients.php,” as shown in Figure 8.

Figure 8: The Check-in victim list
Figure 8: The Check-in victim list
It then periodically monitors the foreground window using the APIs “GetForegroundWindow” and “GetWindowTextW.” Upon identifying a window and confirming its name against a predefined list of bank-related strings, the malware establishes communication with its Command and Control (C&C) server.

The malware facilitates various actions to steal a victim's credentials, such as allowing the operator to block the victim's screen, log keystrokes, and display deceptive pop-up windows, as shown in Figure 10. The malware actively monitors the victim's access to specific financial portals, including several banks and Mercado Bitcoin, which encompasses both traditional banking and cryptocurrency platforms.

Figure 9: Compare the Window's text and the target string
Figure 9: Compare the Window's text and the target string
Figure 10: The deceptive pop-up windows
Figure 10: The deceptive pop-up windows
After obtaining the user's entered login data, the malware initiates communication with its Command and Control (C2) server at hxxp://comunidadebet20102[.]hopto[.]org. Depending on the bank associated with the stolen data, it uploads the information to distinct paths: “04/M/” for Mercado Bitcoin.

Figure 11: The assembly code that uploads stolen data
Figure 11: The assembly code that uploads stolen data
It then transmits a POST request containing essential system details and configures the account information within the “InfoDados” parameter, as seen in Figure 12.

Figure 12: The HTTP POST request for stolen data
Figure 12: The HTTP POST request for stolen data
Older Variant
Additionally, we acquired an older variant of CHAVECLOAK from the check-in site. Its process differs from the previous one, as the ZIP file contains a Delphi executable file embedding the final payload in the RCData section.

Figure 13: The payload in TFORM1
Figure 13: The payload in TFORM1
It begins by retrieving system information to establish a new folder and stores the payload at “C:\Program Files (x86)\Editor-GH-[HEX ID]\Editor-[HEX ID].exe.” Simultaneously, it creates a log file, establishes persistence, and utilizes the PowerShell command “Add-MpPreference –ExclusionPath” to exclude the path “Editor-GH-[HEX ID]” from Windows Defender scans. Subsequently, it sends a check-in request to hxxp://64[.]225[.]32[.]24/desktop/inspecionando.php. Notably, this variant appears to be an earlier version, indicated by the victims' check-in date starting in 2023.

Figure 14: Add registry
Figure 14: Add registry
Figure 15: The Check-in user list
Figure 15: The Check-in user list
It also actively observes user behavior, captures front window text, and harvests personally identifiable information from specified banking and Bitcoin login pages, including names, passwords, and keystrokes. It then transmits the stolen data to the Command and Control (C2) server at hxxp://mariashow[.]ddns[.]net/dtp/cnx.php.

Figure 16: The HTTP data for sending account information
Figure 16: The HTTP data for sending account information
Conclusion
The emergence of the CHAVECLOAK banking Trojan underscores the evolving landscape of cyberthreats targeting the financial sector, specifically focusing on users in Brazil. Utilizing sophisticated techniques, including malicious PDFs, ZIP file downloads, DLL sideloading, and deceptive pop-ups, it joins a cohort of prominent banking trojans that primarily target South America. CHAVECLOAK employs Portuguese language settings, indicating a strategic approach to the region, and actively monitors victims' interactions with financial portals. CHAVECLOAK exemplifies the sophistication of contemporary banking trojans, necessitating continual vigilance and proactive cybersecurity measures to safeguard against evolving threats within the financial landscape of South America.

Fortinet Protections
The malware described in this report are detected and blocked by FortiGuard Antivirus as:

PDF/Agent.72C4!tr
W32/Banker.CNX!tr
FortiGate, FortiMail, FortiClient, and FortiEDR support the FortiGuard AntiVirus service. The FortiGuard AntiVirus engine is a part of each of those solutions. As a result, customers who have these products with up-to-date protections are protected.

The URLs are rated as “Malicious Websites” by the FortiGuard Web Filtering service.

The FortiGuard CDR (content disarm and reconstruction) service can disarm the malicious macros in the document.

We also suggest that organizations go through Fortinet’s free Fortinet Certified Fundamentals (FCF) in cybersecurity training. The training is designed to help end users learn about today's threat landscape and will introduce basic cybersecurity concepts and technology.

FortiGuard IP Reputation and Anti-Botnet Security Service proactively block these attacks by aggregating malicious source IP data from the Fortinet distributed network of threat sensors, CERTs, MITRE, cooperative competitors, and other global sources that collaborate to provide up-to-date threat intelligence about hostile sources.

If you believe this or any other cybersecurity threat has impacted your organization, please contact our Global FortiGuard Incident Response Team.

IOCs
IP
64[.]225[.]32[.]24

URLs
hxxps://webattach.mail.yandex.net/message_part_real/NotaFiscalEsdeletronicasufactrub66667kujhdfdjrWEWGFG09t5H6854JHGJUUR[.]zip
hxxps://goo[.]su/FTD9owO
Hostnames
mariashow[.]ddns[.]net
comunidadebet20102[.]hopto[.]org
Files:
51512659f639e2b6e492bba8f956689ac08f792057753705bf4b9273472c72c4
48c9423591ec345fc70f31ba46755b5d225d78049cfb6433a3cb86b4ebb5a028
4ab3024e7660892ce6e8ba2c6366193752f9c0b26beedca05c57dcb684703006
131d2aa44782c8100c563cd5febf49fcb4d26952d7e6e2ef22f805664686ffff
8b39baec4b955e8dfa585d54263fd84fea41a46554621ee46b769a706f6f965c
634542fdd6581dd68b88b994bc2291bf41c60375b21620225a927de35b5620f9
2ca1b23be99b6d46ce1bbd7ed16ea62c900802d8efff1d206bac691342678e55
