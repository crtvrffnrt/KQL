<div align="center">
  <img src="./logo.png" alt="KQL Hunter logo" width="360">

  <h1>KQL Hunter</h1>

  <p><strong>Compact, practical KQL for hunting, triage, and quick investigation pivots.</strong></p>

  <p>
    <a href="#identity"><img src="https://img.shields.io/badge/identity-0F172A?style=flat-square&logo=microsoft&logoColor=white" alt="Identity"></a>
    <a href="#mailbox"><img src="https://img.shields.io/badge/mailbox-111827?style=flat-square&logo=gmail&logoColor=white" alt="Mailbox"></a>
    <a href="#endpoint"><img src="https://img.shields.io/badge/endpoint-0EA5E9?style=flat-square&logo=windows&logoColor=white" alt="Endpoint"></a>
    <a href="#network"><img src="https://img.shields.io/badge/network-F59E0B?style=flat-square&logo=cloudflare&logoColor=white" alt="Network"></a>
    <a href="#defender"><img src="https://img.shields.io/badge/defender-22C55E?style=flat-square&logo=shield&logoColor=white" alt="Defender"></a>
  </p>

  <p>
    <a href="#identity"><strong>Identity</strong></a> •
    <a href="#mailbox"><strong>Mailbox</strong></a> •
    <a href="#endpoint"><strong>Endpoint</strong></a> •
    <a href="#network"><strong>Network</strong></a> •
    <a href="#defender"><strong>Defender</strong></a>
  </p>
</div>

> A grab-and-go set of queries for everyday defensive hunting.

---

## At a Glance

- Fast triage and hunting queries
- Reusable patterns for common investigations
- Focused on Microsoft Sentinel, Defender, and UAL-style telemetry
- Easy to tweak for your tenant, entity, or time window

## Query Catalog

<!-- BEGIN GENERATED KQL CATALOG -->

### Identity

<details>
<summary><strong>Alert on New Admin Permission</strong><br><sub>Flags directory role assignment activity that grants administrative privileges.</sub></summary>

<br>

**Source:** [`Alertonnewadminpermission.kql`](./Alertonnewadminpermission.kql)
**Tables:** `AuditLogs`
**Use case:** Identity investigation / phishing triage

```kusto
AuditLogs 
| where OperationName == "Add member to role" 
| where parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)) contains "administrator" 
| extend TargetUser_ = tostring(TargetResources[0].userPrincipalName) 
| extend assignedrole_ = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue))) 
| extend oldValue_ = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].oldValue) 
| extend ipAddress_ = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) 
| extend initiatingUser_ = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName) 
| project TimeGenerated,assignedrole_,oldValue_, Identity,parse_json(tostring(InitiatedBy.app)).displayName, TargetUser_, initiatingUser_ 

```

</details>

<details>
<summary><strong>Malicious Sign-In from Blacklisted IP</strong><br><sub>Matches sign-in activity against a curated blacklist of known-bad IP addresses.</sub></summary>

<br>

**Source:** [`MaliciouSignIn-from-BlacklistedIP.kql`](./MaliciouSignIn-from-BlacklistedIP.kql)
**Tables:** `AADSignInEventsBeta`
**Use case:** Identity investigation / phishing triage

```kusto
let BlockList = (externaldata(ip:string)
[@"https://defaultclshl.blob.core.windows.net/files/ipblacklist.txt"]
with(format="txt")
| distinct ip
| where ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
);
AADSignInEventsBeta 
| where Timestamp > ago(1h)
| where IPAddress in (BlockList)

```

</details>

<details>
<summary><strong>MFA Registration After Risky Sign-In</strong><br><sub>Correlates risky sign-ins with subsequent MFA method registration.</sub></summary>

<br>

**Source:** [`malmfareg.kql`](./malmfareg.kql)
**Tables:** `AADSignInEventsBeta`, `CloudAppEvents`
**Use case:** Identity investigation / phishing triage

```kusto
//   Looks for a new MFA method added to an account that was preceded by medium or high risk sign-in session for the same user within maximum 6h timeframe 
// https://github.com/Azure/Azure-Sentinel/blob/cefd53e00a471f32f48a84ea58559df27e6eb82a/Hunting%20Queries/Microsoft%20365%20Defender/Persistence/riskySignInToNewMFAMethod.yaml
let mfaMethodAdded=CloudAppEvents
  | where ActionType =~ "Update user." 
  | where RawEventData has "StrongAuthenticationPhoneAppDetail"
  | where isnotempty(RawEventData.ObjectId) and isnotempty(RawEventData.Target[1].ID)
  | extend AccountUpn = tostring(RawEventData.ObjectId)
  | extend AccountObjectId = tostring(RawEventData.Target[1].ID)
  | project Timestamp,ReportId,MfaAddedTimestamp=Timestamp,AccountUpn,AccountObjectId;
  let usersWithNewMFAMethod=mfaMethodAdded
  | distinct AccountObjectId;
  let hasusersWithNewMFAMethod = isnotempty(toscalar(usersWithNewMFAMethod));
  let riskySignins=AADSignInEventsBeta
  | where hasusersWithNewMFAMethod
  | where AccountObjectId in (usersWithNewMFAMethod)
  | where RiskLevelDuringSignIn in ("50","100") //Medium and High sign-in risk level.
  | where Application in ("Office 365 Exchange Online", "OfficeHome")
  | where isnotempty(SessionId)
  | project Timestamp, ReportId,SignInTimestamp=Timestamp, Application, SessionId, AccountObjectId, IPAddress,RiskLevelDuringSignIn
  | summarize SignInTimestamp=argmin(SignInTimestamp,*) by Application,SessionId, AccountObjectId, IPAddress,RiskLevelDuringSignIn;
  mfaMethodAdded
  | join riskySignins on AccountObjectId
  | where MfaAddedTimestamp - SignInTimestamp < 6h //Time delta between risky sign-in and device registration less than 6h
  | project-away AccountObjectId1

```

</details>

<details>
<summary><strong>OAuth Suspicious Redirect Callback URI</strong><br><sub>Finds OAuth redirect URIs that resemble callback or listener infrastructure.</sub></summary>

<br>

**Source:** [`oauth_suspicious_redirect_callback_uri.kql`](./oauth_suspicious_redirect_callback_uri.kql)
**Tables:** `AuditLogs`
**Use case:** Identity investigation / phishing triage

```kusto
let SuspiciousExactDomains = dynamic([
    "oast.fun", "oast.live", "oast.me", "oast.online", "oast.pro", "oast.site",
    "oastify.com", "interact.sh", "interactsh.com",
    "burpcollaborator.net", "burpcollaborator.com",
    "canarytokens.com", "canarytokens.org",
    "webhook.site", "pipedream.net", "pipedream.com", "requestbin.com", "requestbin.net",
    "requestcatcher.com", "beeceptor.com", "hookdeck.com", "mockbin.org", "postman-echo.com",
    "httpbin.org", "putsreq.com", "smee.io",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev", "ngrok.pizza", "ngrok.pro","msobb.de",
    "trycloudflare.com", "cfargotunnel.com",
    "localtunnel.me", "loca.lt", "serveo.net", "localhost.run", "pagekite.me", "telebit.io",
    "inlets.dev", "bore.pub", "zrok.io", "zrok.cloud"
]);
let SuspiciousHostKeywords = dynamic([
    "webhook", "webhooks", "receiver", "listener",
    "oast", "interact", "burpcollaborator", "canarytoken",
    "requestbin", "requestcatcher", "beeceptor", "hookdeck", "mockbin",
    "ngrok", "cloudflared", "argotunnel", "localtunnel", "serveo", "pagekite", "telebit", "zrok"
]);
let SuspiciousTlds = dynamic([
    "fun", "site", "click", "top", "xyz", "icu", "monster",
    "cyou", "quest", "bond", "lol", "sbs", "buzz", "cam", "work", "rest"
]);
let BenignRedirectHosts = dynamic([
    // Add tenant-specific known-good redirect hosts here.
    // Examples:
    // "login.microsoftonline.com",
    // "localhost",
    // "127.0.0.1"
]);
AuditLogs
| where TargetResources has "AppAddress" or TargetResources has "http"
| extend InitiatedByJson = parse_json(tostring(InitiatedBy))
| extend
    InitiatedByUser = tostring(InitiatedByJson.user.userPrincipalName),
    InitiatedByUserId = tostring(InitiatedByJson.user.id),
    InitiatedByApp = tostring(InitiatedByJson.app.displayName),
    InitiatedByAppId = tostring(InitiatedByJson.app.appId),
    InitiatedByIpAddress = tostring(InitiatedByJson.user.ipAddress)
| mv-expand TargetResource = TargetResources
| extend
    TargetResourceDisplayName = tostring(TargetResource.displayName),
    TargetResourceType = tostring(TargetResource.type),
    TargetResourceId = tostring(TargetResource.id),
    ModifiedProperties = TargetResource.modifiedProperties
| mv-expand ModifiedProperty = ModifiedProperties
| extend
    ModifiedPropertyName = tostring(ModifiedProperty.displayName),
    ModifiedPropertyNewValue = tostring(ModifiedProperty.newValue),
    ModifiedPropertyOldValue = tostring(ModifiedProperty.oldValue)
| where ModifiedPropertyName =~ "AppAddress"
| extend UrlCandidates = extract_all(
    @"(https?://[^\s""'<>;,\]\}\\]+)",
    strcat(ModifiedPropertyNewValue, " ", ModifiedPropertyOldValue)
)
| mv-expand RedirectUri = UrlCandidates
| extend RedirectUri = trim(@" .""'<>", tostring(RedirectUri))
| where isnotempty(RedirectUri)
| extend ParsedRedirectUri = parse_url(RedirectUri)
| extend
    RedirectHost = tolower(tostring(ParsedRedirectUri.Host)),
    RedirectScheme = tolower(tostring(ParsedRedirectUri.Scheme)),
    RedirectPath = tostring(ParsedRedirectUri.Path)
| extend RedirectHostParts = split(RedirectHost, ".")
| extend RedirectTld = tostring(RedirectHostParts[array_length(RedirectHostParts) - 1])
| where RedirectHost !in~ (BenignRedirectHosts)
| extend
    MatchedExactDomain = iff(RedirectHost has_any (SuspiciousExactDomains), true, false),
    MatchedKeyword = iff(RedirectHost has_any (SuspiciousHostKeywords), true, false),
    MatchedSuspiciousTld = iff(RedirectTld in~ (SuspiciousTlds), true, false)
| where MatchedExactDomain or MatchedKeyword or MatchedSuspiciousTld
| extend DetectionReason = strcat_array(
    pack_array(
        iff(MatchedExactDomain, "Known suspicious redirect/callback domain", ""),
        iff(MatchedKeyword, "Suspicious callback/listener keyword in redirect host", ""),
        iff(MatchedSuspiciousTld, "Suspicious or abuse-prone redirect TLD", "")
    ),
    "; "
)
| extend DetectionReason = trim(@";\s", replace_string(DetectionReason, "; ;", ";"))
| project
    TimeGenerated,
    OperationName,
    Result,
    Category,
    ActivityDateTime,
    InitiatedByUser,
    InitiatedByUserId,
    InitiatedByApp,
    InitiatedByAppId,
    InitiatedByIpAddress,
    TargetResourceDisplayName,
    TargetResourceType,
    TargetResourceId,
    ModifiedPropertyName,
    RedirectUri,
    RedirectHost,
    RedirectTld,
    DetectionReason,
    ModifiedPropertyNewValue,
    ModifiedPropertyOldValue,
    CorrelationId,
    AADOperationType,
    LoggedByService
| order by TimeGenerated desc

```

</details>

<details>
<summary><strong>Risky or VIP User Security Info Change</strong><br><sub>Correlates risky or VIP users with recent security-info changes.</sub></summary>

<br>

**Source:** [`risky_or_vip_user_security_info_change.kql`](./risky_or_vip_user_security_info_change.kql)
**Tables:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`
**Use case:** Identity investigation / phishing triage

```kusto
let queryperiod = 3d;
let queryfrequency = 2h;
let security_info_actions = dynamic(["User registered security info", "User changed default security info", "User deleted security info", "Admin updated security info", "Admin deleted security info", "Admin registered security info"]);
// Get users with a risk state in the last 7 days from SignInLogs
let risky_users_signin = 
    SigninLogs
    | where TimeGenerated > ago(queryperiod)
    | where RiskState != "none"
    | distinct UserPrincipalName;
// Get users with a risk state in the last 7 days from AADNonInteractiveUserSignInLogs
let risky_users_noninteractive = 
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(queryperiod)
    | where RiskState != "none"
    | distinct UserPrincipalName;
// Combine both risky user datasets
let risky_users = risky_users_signin
    | union risky_users_noninteractive;
// Get VIP users from Sentinel Watchlist
let VIPUsers = 
    _GetWatchlist('VIPUsers')
    | project SearchKey;
// Combine risky users and VIP users
let monitored_users = risky_users
    | union VIPUsers;
AuditLogs
| where TimeGenerated > ago(queryfrequency)
| where Category =~ "UserManagement"
| where ActivityDisplayName in (security_info_actions)
| extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
| extend InitiatingAppServicePrincipalId = tostring(InitiatedBy.app.servicePrincipalId)
| extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
| extend InitiatingIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| mv-apply TargetResource = TargetResources on 
    (
    where TargetResource.type =~ "User"
    | extend TargetUserPrincipalName = tostring(TargetResource.userPrincipalName)
    )
| join kind=inner (monitored_users) on $left.InitiatingUserPrincipalName == $right.UserPrincipalName
| summarize 
    Start=min(TimeGenerated),
    End=max(TimeGenerated),
    Actions = make_set(ResultReason, MaxSize=8)
    by
    InitiatingAppName,
    InitiatingAppServicePrincipalId, 
    InitiatingUserPrincipalName,
    InitiatingAadUserId,
    InitiatingIpAddress,
    TargetUserPrincipalName,
    Result
| extend
    InitiatingAccountName = tostring(split(InitiatingUserPrincipalName, "@")[0]),
    InitiatingAccountUPNSuffix = tostring(split(InitiatingUserPrincipalName, "@")[1]), 
    TargetName = iff(tostring(TargetUserPrincipalName) has "[", "", tostring(split(TargetUserPrincipalName, '@', 0)[0])),
    TargetUPNSuffix = iff(tostring(TargetUserPrincipalName) has "[", "", tostring(split(TargetUserPrincipalName, '@', 1)[0]))

```

</details>

### Mailbox

<details>
<summary><strong>AiTM Phishing Case Detection</strong><br><sub>Correlates suspicious email and attachment activity that may indicate adversary-in-the-middle phishing.</sub></summary>

<br>

**Source:** [`AiTMphishingCaseDectection.kql`](./AiTMphishingCaseDectection.kql)
**Tables:** `EmailEvents`, `EmailAttachmentInfo`
**Use case:** Mailbox investigation / phishing triage

```kusto
EmailEvents
| where Timestamp > ago(1h)
| where Subject contains "Message" 
| where Subject contains "Voice"
| join kind=inner (EmailAttachmentInfo 
| where FileName contains "Message"
| where FileName contains ".htm"
) on NetworkMessageId

```

</details>

<details>
<summary><strong>Malicious URL Click</strong><br><sub>Flags URL click activity from known-bad IP addresses.</sub></summary>

<br>

**Source:** [`malurlclick.kql`](./malurlclick.kql)
**Tables:** `UrlClickEvents`
**Use case:** Mailbox investigation / phishing triage

```kusto
let BlockList = (externaldata(ip:string)
[@"https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"]
with(format="txt")
| distinct ip
| where ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
);
UrlClickEvents
| where Timestamp > ago(24h)
| where IPAddress in (BlockList)

```

</details>

<details>
<summary><strong>Potential Spoofing Mail</strong><br><sub>Flags email authentication failures that may indicate domain spoofing.</sub></summary>

<br>

**Source:** [`potentialspoofingmail.kql`](./potentialspoofingmail.kql)
**Tables:** `EmailEvents`
**Use case:** Mailbox investigation / phishing triage

```kusto
let trustet=dynamic(["example@mail.de"]);
EmailEvents
| where Timestamp > ago (24h)
| where SenderMailFromAddress !in (trustet)
| where SenderIPv4 !startswith "1.1." // 
| where RecipientEmailAddress endswith "domain.de"
| where SenderMailFromAddress endswith "domain.de"
| mv-expand todynamic(AuthenticationDetails)
| where AuthenticationDetails.SPF in ("fail","softfail")

```

</details>

<details>
<summary><strong>UAL Malicious Mail Access</strong><br><sub>Surfaces mailbox item access from UAL MailItemsAccessed records.</sub></summary>

<br>

**Source:** [`UAL-MaliciousMailAccess.kql`](./UAL-MaliciousMailAccess.kql)
**Tables:** `UAL`
**Use case:** Mailbox investigation / phishing triage

```kusto
UAL
| where Operation == "MailItemsAccessed"
| extend AuditData = parse_json(AuditData)
| where AuditData.AppAccessContext.AADSessionId in ("003066ba-84c3-5438-5423-f7f392e0dbbc","00308dca-a420-2237-228b-b61ee5892f38") //Change SessionId here
| extend CreationTime = todatetime(AuditData.CreationTime),UserId = tostring(AuditData.UserId),ClientIP = tostring(AuditData.ClientIPAddress),SessionId = tostring(AuditData.AppAccessContext.AADSessionId)
| mv-expand Folder = AuditData.Folders
| mv-expand Item = Folder.FolderItems
| extend InternetMessageId = tostring(Item.InternetMessageId),Subject = tostring(Item.Subject),ItemCreationTime = todatetime(Item.CreationTime),SizeInBytes = tolong(Item.SizeInBytes),FolderPath = tostring(Folder.Path)
| where isnotempty(InternetMessageId)
| project TimeGenerated=CreationTime,ItemCreationTime,UserId,ClientIP,SessionId,FolderPath,InternetMessageId,Subject,SizeInBytes,RecordId
| summarize arg_min(TimeGenerated, *) by InternetMessageId

```

</details>

### Endpoint

<details>
<summary><strong>Add Local Admin</strong><br><sub>Detects users added to the local Administrators group.</sub></summary>

<br>

**Source:** [`addlocaladmin.kql`](./addlocaladmin.kql)
**Tables:** `DeviceEvents`
**Use case:** Endpoint investigation / host triage

```kusto
DeviceEvents
| where Timestamp > ago(3h)
| where ActionType == "UserAccountAddedToLocalGroup"
| extend LocalGroupSID = AccountSid
| where LocalGroupSID == "S-1-5-32-544"

```

</details>

<details>
<summary><strong>Detect Macro Documents</strong><br><sub>Flags Office processes interacting with macro-enabled file types.</sub></summary>

<br>

**Source:** [`detectmacrodocuments.kql`](./detectmacrodocuments.kql)
**Tables:** `DeviceProcessEvents`
**Use case:** Endpoint investigation / host triage

```kusto
let unkommonfiletypes = dynamic([".docm",".xlsm",".dot",".wbk",".dotm",".docb",".xlsm",".xlm",".xltm",".xlam",".xla",".ppt",".pptm",".potm",".ppsm",".sldm"]);
let Officeprozesses = dynamic(["WINWORD","EXCEL", "PowerPoint", "Outlook"]);
DeviceProcessEvents 
| where Timestamp > ago (1d)
| where FileName has_any (Officeprozesses)
| where ProcessCommandLine has_any (unkommonfiletypes)




```

</details>

<details>
<summary><strong>Detect Malicious or Unwanted Software</strong><br><sub>Hunts for known malicious or unwanted process names on endpoints.</sub></summary>

<br>

**Source:** [`DetectMaliciousorunwantedSoftware.kql`](./DetectMaliciousorunwantedSoftware.kql)
**Tables:** `DeviceProcessEvents`
**Use case:** Endpoint investigation / host triage

```kusto
let malexe=dynamic(["Tor.exe","Nmap.exe","zenmap.exe", "mimikatz.exe","psexec.exe","psexec64.exe","kis21.exe","nc.exe","advanced_ip_scanner.exe"]);
DeviceProcessEvents 
| where Timestamp > ago (1d)
| where DeviceId != @"e17bbb60a334dde9d0958c2233d89d37d51d278"
| where FileName in~ (malexe)

```

</details>

<details>
<summary><strong>Execution of Malicious File Type</strong><br><sub>Flags suspicious double-extension file execution patterns.</sub></summary>

<br>

**Source:** [`executionofmaliciousfiletype`](./executionofmaliciousfiletype)
**Tables:** `DeviceProcessEvents`
**Use case:** Endpoint investigation / host triage

```kusto
let Filetype = dynamic([".jpg.exe",".doc.exe",".docx.exe",".xls.exe",".xlsx.exe",".png.exe",".pdf.exe",".jpg.msi",".doc.msi",".docx.msi",".xls.msi",".xlsx.msi",".png.msi",".pdf.msi",".jpg.ps1",".doc.ps1",".docx.ps1",".xls.ps1",".xlsx.ps1",".png.ps1",".pdf.ps1",".jpg.bat",".doc.bat",".docx.bat",".xls.bat",".xlsx.bat",".png.bat",".pdf.bat",".jpg.cmd",".doc.cmd",".docx.cmd",".xls.cmd",".xlsx.cmd",".png.cmd",".pdf.cmd"]);
DeviceProcessEvents 
| where Timestamp > ago(1h) 
| where FileName has_any (Filetype)

```

</details>

<details>
<summary><strong>Local Reconnaissance Detection</strong><br><sub>Detects common Windows discovery and local reconnaissance commands.</sub></summary>

<br>

**Source:** [`localrecondetect.kql`](./localrecondetect.kql)
**Tables:** `DeviceProcessEvents`
**Use case:** Endpoint investigation / host triage

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (InitiatingProcessCommandLine == 'gpresult /z' 
or InitiatingProcessCommandLine == 'gpresult /v' 
or InitiatingProcessCommandLine == 'gpresult' 
or InitiatingProcessCommandLine == 'net view' 
or InitiatingProcessCommandLine == 'net view /domain' 
or InitiatingProcessCommandLine == 'netstat' 
or InitiatingProcessCommandLine == 'netstat -nab' 
or InitiatingProcessCommandLine == 'netstat -nao' 
or InitiatingProcessCommandLine == 'netstat -ano'
or InitiatingProcessCommandLine == 'nslookup 127.0.0.1' 
or InitiatingProcessCommandLine == 'arp -a' 
or InitiatingProcessCommandLine == 'net share' 
or InitiatingProcessCommandLine == 'net use' 
or InitiatingProcessCommandLine == 'systeminfo' 
or InitiatingProcessCommandLine == 'net user' 
or InitiatingProcessCommandLine == 'net user administrator' 
or InitiatingProcessCommandLine == 'net user /domain' 
or InitiatingProcessCommandLine == 'net group' 
or InitiatingProcessCommandLine == 'net group /domain' 
or InitiatingProcessCommandLine == 'net localgroup' 
or InitiatingProcessCommandLine == 'net localgroup' 
or InitiatingProcessCommandLine == 'net localgroup Administrators' 
or InitiatingProcessCommandLine == 'net group \"Domain Computers\" /domain' 
or InitiatingProcessCommandLine == 'net group \"Domain Admins\" /domain' 
or InitiatingProcessCommandLine == 'net group \"Domain Controllers\" /domain' 
or InitiatingProcessCommandLine == @'dir \\"%programfiles%\\"' 
or InitiatingProcessCommandLine == 'net group \"Exchange Servers\" /domain' 
or InitiatingProcessCommandLine == 'net accounts' 
or InitiatingProcessCommandLine == 'net accounts /domain' 
or InitiatingProcessCommandLine == 'net view 127.0.0.1 /all' 
or InitiatingProcessCommandLine == 'net session' 
or InitiatingProcessCommandLine == 'icacls "C:/Windows/system32/config/sam"'
or InitiatingProcessCommandLine == 'icacls "C:/Windows/system32/config/system"'
or InitiatingProcessCommandLine == 'icacls "C:/Windows/system32/config/security"'
or InitiatingProcessCommandLine == 'icacls $env:windir/system32/config/'
or InitiatingProcessCommandLine == 'icacls %windir%/system32/config'
or InitiatingProcessCommandLine == 'ipconfig /displaydns')

```

</details>

<details>
<summary><strong>Possible Linux Reverse Shell Script Content</strong><br><sub>Finds script content consistent with a possible Linux reverse shell.</sub></summary>

<br>

**Source:** [`possible-linux-reverse-shell-scriptcontent.kql`](./possible-linux-reverse-shell-scriptcontent.kql)
**Tables:** `DeviceEvents`
**Use case:** Endpoint investigation / host triage

```kusto
// Detection of possible Unix/Linux reverse shells based on DeviceEvents AdditionalFields.ScriptContent.
// Author: Patrick Binder
let Port = @"(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])";
let IPv4 = @"(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})";
let IPv6 = @"(?:\[[0-9a-fA-F:.]+\]|[0-9a-fA-F]{0,4}:[0-9a-fA-F:.]+)";
let Hostname = @"(?:[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}\.[a-zA-Z]{2,63}|[a-zA-Z0-9][a-zA-Z0-9.-]{1,253})";
let Host = strcat(@"(?:", IPv4, @"|", IPv6, @"|", Hostname, @")");
let Shell = @"(?:/usr/bin/|/bin/|/usr/local/bin/)?(?:bash|sh|dash|ash|zsh|ksh|mksh|csh|tcsh)";
let DevTcpUdp = strcat(@"/dev/(?:tcp|udp)/", Host, @"/", Port);
let RxClassicDevTcp = strcat(
    Shell, @"\s+-i\b[\s\S]{0,200}",
    DevTcpUdp,
    @"[\s\S]{0,200}(?:0>&1|2>&1|>&\d+|>\&\d+|<&\d+)"
);
let RxFdDevTcp = strcat(
    @"(?:exec\s+\d+<>|\d+<>|<>)[\s\S]{0,120}",
    DevTcpUdp,
    @"[\s\S]{0,300}(?:", Shell, @"|cat\s+<&\d+|while\s+read|2>&\d+|>&\d+|<&\d+)"
);
let RxNetcatTargetFirst = strcat(
    @"(?:^|[\s;|&])(?:nc|ncat|netcat|nc\.traditional|nc\.openbsd)\s+(?:-[a-z0-9]+\s+){0,8}",
    Host,
    @"\s+",
    Port,
    @"[\s\S]{0,160}(?:\s-[ec]\s+|\s--exec\s+|\s--sh-exec\s+)",
    Shell
);
let RxNetcatShellFirst = strcat(
    @"(?:^|[\s;|&])(?:nc|ncat|netcat|nc\.traditional|nc\.openbsd)[\s\S]{0,160}(?:\s-[ec]\s+|\s--exec\s+|\s--sh-exec\s+)",
    Shell,
    @"[\s\S]{0,160}",
    Host,
    @"\s+",
    Port
);
let RxCurlWgetTelnet = strcat(
    @"(?:curl|wget)[\s\S]{0,150}telnet://",
    Host,
    @":",
    Port,
    @"[\s\S]{0,300}\|\s*",
    Shell
);
let RxPythonSocket = strcat(
    @"python(?:\d+(?:\.\d+)?)?\s+-c\s+['""][\s\S]{0,900}(?:socket\.socket|create_connection)[\s\S]{0,900}(?:connect\s*\(\s*\(?\s*['""]",
    Host,
    @"['""]\s*,\s*",
    Port,
    @"|create_connection\s*\(\s*\(?\s*['""]",
    Host,
    @"['""]\s*,\s*",
    Port,
    @")[\s\S]{0,900}(?:dup2|fileno\s*\(\)|pty\.spawn)[\s\S]{0,300}",
    Shell
);
let RxPythonEnv = strcat(
    @"(?:rhost|lhost)\s*=\s*['""]?",
    Host,
    @"['""]?[\s\S]{0,200}(?:rport|lport)\s*=\s*['""]?",
    Port,
    @"['""]?[\s\S]{0,1200}python(?:\d+(?:\.\d+)?)?\s+-c\s+['""][\s\S]{0,1200}(?:connect|dup2|pty\.spawn)[\s\S]{0,300}",
    Shell
);
let RxPerlSocket = strcat(
    @"perl\s+-e\s+['""][\s\S]{0,1200}(?:\$i\s*=\s*['""]",
    Host,
    @"['""]|\$p\s*=\s*",
    Port,
    @"|inet_aton\s*\(\s*['""]",
    Host,
    @"['""]\s*\))[\s\S]{0,1200}(?:socket\s*\(|connect\s*\(|sockaddr_in)[\s\S]{0,1200}(?:open\s*\(\s*STDIN|open\s*\(\s*STDOUT|open\s*\(\s*STDERR)[\s\S]{0,500}exec\s*\([\s\S]{0,120}",
    Shell
);
let RxSocat = strcat(
    @"(?:^|[\s;|&])socat\s+(?:-[^\s]+\s+){0,8}(?:tcp|tcp4|tcp6|udp|udp4|udp6|openssl):",
    Host,
    @":",
    Port,
    @"[\s\S]{0,240}(?:exec|system):",
    Shell
);
let RxZshZtcp = strcat(
    @"zmodload\s+zsh/net/tcp[\s\S]{0,240}\bztcp\s+",
    Host,
    @"\s+",
    Port,
    @"[\s\S]{0,300}(?:\$reply|0>&\$reply|>&\$reply|2>&\$reply)"
);
let RxNodeChildProcess = strcat(
    @"(?:require\s*\(['""]child_process['""]\)|child_process)[\s\S]{0,400}(?:exec|spawn)[\s\S]{0,400}(?:(?:nc|ncat|netcat)[\s\S]{0,160}(?:-[ec]|--exec|--sh-exec)[\s\S]{0,160}",
    Host,
    @"[\s\S]{0,80}",
    Port,
    @"|",
    DevTcpUdp,
    @")"
);
let ReverseShellRegex = strcat(
    @"(?i)(",
    RxClassicDevTcp,
    @"|",
    RxFdDevTcp,
    @"|",
    RxNetcatTargetFirst,
    @"|",
    RxNetcatShellFirst,
    @"|",
    RxCurlWgetTelnet,
    @"|",
    RxPythonSocket,
    @"|",
    RxPythonEnv,
    @"|",
    RxPerlSocket,
    @"|",
    RxSocat,
    @"|",
    RxZshZtcp,
    @"|",
    RxNodeChildProcess,
    @")"
);
DeviceEvents
| extend EventTime = coalesce(
    column_ifexists("Timestamp", datetime(null)),
    column_ifexists("TimeGenerated", datetime(null))
)
| extend ScriptContent = tostring(parse_json(AdditionalFields).ScriptContent)
| where isnotempty(ScriptContent)
| where ScriptContent has_any (
    "bash", "sh", "dash", "ash", "zsh", "ksh", "mksh", "csh", "tcsh",
    "/dev/tcp", "/dev/udp", "nc", "ncat", "netcat", "socat", "ztcp",
    "telnet://", "socket", "dup2", "pty.spawn", "child_process"
)
| where ScriptContent matches regex ReverseShellRegex
| extend TargetRaw = coalesce(
    extract(@"/dev/(?:tcp|udp)/([^/\s]+)/", 1, ScriptContent),
    extract(@"(?i)telnet://([^:/\s]+):", 1, ScriptContent),
    extract(@"(?i)(?:tcp|tcp4|tcp6|udp|udp4|udp6|openssl):([^:\s]+):", 1, ScriptContent),
    extract(@"(?i)\bztcp\s+([^\s]+)\s+", 1, ScriptContent),
    extract(@"(?i)\b(?:nc|ncat|netcat|nc\.traditional|nc\.openbsd)\s+(?:-[a-z0-9]+\s+){0,8}([^\s]+)\s+\d+", 1, ScriptContent),
    extract(@"(?i)connect\s*\(\s*\(?\s*['""]([^'""]+)['""]\s*,", 1, ScriptContent),
    extract(@"(?i)create_connection\s*\(\s*\(?\s*['""]([^'""]+)['""]\s*,", 1, ScriptContent),
    extract(@"(?i)\$i\s*=\s*['""]([^'""]+)['""]", 1, ScriptContent),
    extract(@"(?i)(?:RHOST|LHOST)\s*=\s*['""]?([^'""]+?)['""]?(?:;|\s)", 1, ScriptContent)
)
| extend Target = replace_regex(tostring(TargetRaw), @"^\[|\]$", "")
| where isnotempty(Target)
| extend TargetIPv4 = iff(Target matches regex strcat(@"^", IPv4, @"$"), Target, "")
| extend TargetIPv6 = iff(Target matches regex strcat(@"^", IPv6, @"$") and isempty(TargetIPv4), Target, "")
| extend TargetHostname = iff(isempty(TargetIPv4) and isempty(TargetIPv6), Target, "")
| project
    EventTime,
    DeviceId,
    DeviceName,
    ActionType,
    ScriptContent,
    TargetIPv4,
    TargetIPv6,
    TargetHostname,
    SHA256

```

</details>

<details>
<summary><strong>Suspicious Registry Key</strong><br><sub>Detects suspicious Winlogon AutoAdminLogon registry changes.</sub></summary>

<br>

**Source:** [`suspiciousregkey`](./suspiciousregkey)
**Tables:** `DeviceRegistryEvents`
**Use case:** Endpoint investigation / host triage

```kusto
DeviceRegistryEvents 
| where Timestamp > ago(24h)
| where (RegistryKey contains @"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon")

```

</details>

### Network

<details>
<summary><strong>Basic Auth Brute Force Apache Syslog</strong><br><sub>Detects repeated Apache 401 responses consistent with brute-force probing.</sub></summary>

<br>

**Source:** [`BasicAuthBruteforceApache_Syslog`](./BasicAuthBruteforceApache_Syslog)
**Tables:** `ApacheHTTPServer_CL`
**Use case:** Network investigation / IP and scanning triage

```kusto
ApacheHTTPServer_CL
| where TimeGenerated > ago(1m)
| where RawData matches regex @'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[.*\]\s\"(GET|POST).*?\"\s([1-5][0-9]{2})\s(\d+)\s\"(.*?)\"\s\"(.*?)\".*'
| extend EventProduct = 'Apache'
| extend EventType = 'AccessLog'
| extend EventData = split(RawData, '"')
| extend SubEventData0 = split(trim_start(@' ', (trim_end(@' ', tostring(EventData[0])))), ' ')
| extend SubEventData1 = split(EventData[1], ' ')
| extend SubEventData2 = split(trim_start(@' ', (trim_end(@' ', tostring(EventData[2])))), ' ')
| extend SrcIpAddr = tostring(SubEventData0[0])
| extend ClientIdentity = SubEventData0[1]
| extend SrcUserName = SubEventData0[2]
| extend EventStartTime = todatetime(replace(@'\/', @'-', replace(@'(\d{2}\/\w{3}\/\d{4}):(\d{2}\:\d{2}\:\d{2})', @'\1 \2', extract(@'\[(.*?)\+\d+\]', 1, RawData))))
//| extend EventStartTime = strcat(SubEventData0[3], SubEventData0[4])
| extend HttpRequestMethod = SubEventData1[0]
| extend UrlOriginal = SubEventData1[1]
| extend HttpVersion = SubEventData1[2]
| extend HttpStatusCode = SubEventData2[0]
| extend HttpResponseBodyBytes = SubEventData2[1]
| extend HttpReferrerOriginal = EventData[3]
| extend HttpUserAgentOriginal = EventData[5]
| where HttpRequestMethod == "GET"
| where HttpStatusCode !startswith "20"
| where HttpStatusCode startswith "401"
//Define Directory here
| where UrlOriginal startswith "/admin"
| where isnotempty(SrcUserName)
| where SrcUserName != "-"
| sort by TimeGenerated desc
| project TimeGenerated, EventProduct, SrcIpAddr, UrlOriginal, HttpStatusCode, Computer, Type
| summarize Failed = count() by (tostring(SrcIpAddr)), Computer
//Customize Threshold
| where Failed > 3

```

</details>

<details>
<summary><strong>Directory Brute Force Apache Syslog</strong><br><sub>Detects repeated Apache 401 responses consistent with brute-force probing.</sub></summary>

<br>

**Source:** [`DirBruteforceApache_Syslog`](./DirBruteforceApache_Syslog)
**Tables:** `ApacheHTTPServer_CL`
**Use case:** Network investigation / IP and scanning triage

```kusto
ApacheHTTPServer_CL
| where TimeGenerated > ago(5m)
| where RawData matches regex @'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\[.*\]\s\"(GET|POST).*?\"\s([1-5][0-9]{2})\s(\d+)\s\"(.*?)\"\s\"(.*?)\".*'
| extend EventProduct = 'Apache'
| extend EventType = 'AccessLog'
| extend EventData = split(RawData, '"')
| extend SubEventData0 = split(trim_start(@' ', (trim_end(@' ', tostring(EventData[0])))), ' ')
| extend SubEventData1 = split(EventData[1], ' ')
| extend SubEventData2 = split(trim_start(@' ', (trim_end(@' ', tostring(EventData[2])))), ' ')
| extend SrcIpAddr = tostring(SubEventData0[0])
| extend ClientIdentity = SubEventData0[1]
| extend SrcUserName = SubEventData0[2]
| extend EventStartTime = todatetime(replace(@'\/', @'-', replace(@'(\d{2}\/\w{3}\/\d{4}):(\d{2}\:\d{2}\:\d{2})', @'\1 \2', extract(@'\[(.*?)\+\d+\]', 1, RawData))))
//| extend EventStartTime = strcat(SubEventData0[3], SubEventData0[4])
| extend HttpRequestMethod = SubEventData1[0]
| extend UrlOriginal = SubEventData1[1]
| extend HttpVersion = SubEventData1[2]
| extend HttpStatusCode = SubEventData2[0]
| extend HttpResponseBodyBytes = SubEventData2[1]
| extend HttpReferrerOriginal = EventData[3]
| extend HttpUserAgentOriginal = EventData[5]
| where HttpRequestMethod == "GET"
| where HttpStatusCode !startswith "20"
| sort by TimeGenerated desc
| project TimeGenerated, EventProduct, SrcIpAddr, UrlOriginal, HttpStatusCode, Computer, Type
| summarize Failed = count() by (tostring(SrcIpAddr)), Computer
//Attention: the Value 25 only works with honypot: in a productive Used Apache Server this value should be higher
| where Failed > 25

```

</details>

<details>
<summary><strong>Find Botnet IP in Event</strong><br><sub>Matches known botnet IP reputation data across identity, email, and endpoint telemetry.</sub></summary>

<br>

**Source:** [`findbotnetipinevent.kql`](./findbotnetipinevent.kql)
**Tables:** `AADSignInEventsBeta`, `AADSpnSignInEventsBeta`, `IdentityLogonEvents`, `EmailEvents`, `UrlClickEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`
**Use case:** Network investigation / IP and scanning triage

```kusto
let IPs = (externaldata(ip:string)
[@"https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"]
with(format="txt")
| distinct ip
| where ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
);
//Query Search for current malicious Botnet IPs in multible Tables
union AADSignInEventsBeta,AADSpnSignInEventsBeta,DeviceNetworkEvents, EmailEvents, IdentityLogonEvents, DeviceLogonEvents, UrlClickEvents
| where Timestamp > ago(1h)
| where IPAddress in (IPs) or RemoteIP in (IPs) or SenderIPv4 in (IPs)
| project-rename ReportId = ReportId_long

```

</details>

<details>
<summary><strong>IP Investigation</strong><br><sub>Pivots a source IP across identity, email, endpoint, and cloud telemetry.</sub></summary>

<br>

**Source:** [`IPinvestigation.kql`](./IPinvestigation.kql)
**Tables:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADSignInEventsBeta`, `AADSpnSignInEventsBeta`, `AADServicePrincipalSignInLogs`, `AADUserRiskEvents`, `CloudAppEvents`, `IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents`, `EmailEvents`, `UrlClickEvents`, `OfficeActivity`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceEvents`, `DeviceLogonEvents`, `SecurityEvent`, `SecurityAlert`, `AzureActivity`, `BehaviorAnalytics`, `MicrosoftGraphActivityLogs`
**Use case:** Network investigation / IP and scanning triage

```kusto
let ip = '13.74.111.192'; // IP to search for
let timeframe = ago(10d); // Time range
union isfuzzy=true
  IdentityLogonEvents,
  IdentityQueryEvents,
  IdentityDirectoryEvents,
  EmailEvents,
  UrlClickEvents,
  DeviceNetworkEvents,
  DeviceFileEvents,
  DeviceLogonEvents,
  DeviceEvents,
  BehaviorAnalytics,
  CloudAppEvents,
  AADSpnSignInEventsBeta,
  AADSignInEventsBeta,
  AADNonInteractiveUserSignInLogs,
  AADServicePrincipalSignInLogs,
  AADUserRiskEvents,
  SigninLogs,
  OfficeActivity,
  AzureActivity,
  MicrosoftGraphActivityLogs,
  SecurityEvent,
  SecurityAlert
| where TimeGenerated >= timeframe
| where 
    LocalIP == ip or 
    FileOriginIP == ip or 
    RequestSourceIP == ip or 
    SenderIPv4 == ip or 
    SenderIPv6 == ip or 
    IPAddress == ip or 
    SourceIPAddress == ip or 
    ClientIP == ip or 
    RemoteIP == ip or 
    DestinationIPAddress == ip or 
    CallerIpAddress == ip or 
    tostring(parse_json(ExtendedProperties)["Client IP Address"]) == ip or 
    tostring(IpAddress) == ip

```

</details>

<details>
<summary><strong>Malicious Network Connection</strong><br><sub>Identifies endpoint connections to known-bad IP addresses.</sub></summary>

<br>

**Source:** [`malnetconnect.kql`](./malnetconnect.kql)
**Tables:** `DeviceNetworkEvents`
**Use case:** Network investigation / IP and scanning triage

```kusto
let BlockList = (externaldata(ip:string)
[@"https://staticprivatecontent.blob.core.windows.net/$web/ipblacklist.txt"]
with(format="txt")
| distinct ip
| where ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
);
DeviceNetworkEvents 
| where Timestamp > ago(1h)
| where DeviceId != "1586d74a9f37323d27f7e29ec1a370df6b813191"
| where RemoteIP in (BlockList)
| summarize arg_max(Timestamp,*) by DeviceName

```

</details>

<details>
<summary><strong>Malicious URL Detected</strong><br><sub>Searches endpoint telemetry for contact with malicious URLs from URLHaus.</sub></summary>

<br>

**Source:** [`malurldetected.kql`](./malurldetected.kql)
**Tables:** `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceEvents`
**Use case:** Network investigation / IP and scanning triage

```kusto
let urlhouseurl = (externaldata(mal_url: string)
[@"https://urlhaus.abuse.ch/downloads/text_online/"]
with (format="txt"))
| project mal_url;
search in (DeviceNetworkEvents,DeviceFileEvents, DeviceEvents)
Timestamp > ago (1h)
| where RemoteUrl in (urlhouseurl) or FileOriginUrl in (urlhouseurl)
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountUpn,FolderPath , ReportId

```

</details>

<details>
<summary><strong>Nmap Activity Detected</strong><br><sub>Detects network scanning behavior and ties it back to signed-in users when available.</sub></summary>

<br>

**Source:** [`nmapactivitydetected.kql`](./nmapactivitydetected.kql)
**Tables:** `DeviceNetworkEvents`
**Use case:** Network investigation / IP and scanning triage

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName contains "nmap"
| summarize RemotePortCount=dcount(RemotePort) by Timestamp, DeviceName,LocalIP,RemoteIP,RemoteUrl, InitiatingProcessFileName,  InitiatingProcessCommandLine, InitiatingProcessFolderPath, ReportId, DeviceId
| where RemoteUrl !contains "." or RemoteUrl !contains "0" or RemoteUrl !contains ":" or RemoteUrl !contains "%" or RemoteUrl !contains "http"
| where DeviceId != "1586d74a9f37323d27f7e29ec1a370df6b813191"

```

</details>

<details>
<summary><strong>Nmap Vulnerability Scan</strong><br><sub>Detects network scanning behavior and ties it back to signed-in users when available.</sub></summary>

<br>

**Source:** [`nmapvulnscan.kql`](./nmapvulnscan.kql)
**Tables:** `DeviceNetworkEvents`
**Use case:** Network investigation / IP and scanning triage

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName contains "nmap"
| summarize RemotePortCount=dcount(RemotePort) by Timestamp, DeviceName,LocalIP,RemoteIP,RemoteUrl, InitiatingProcessFileName,  InitiatingProcessCommandLine, InitiatingProcessFolderPath, ReportId, DeviceId
| where RemoteUrl contains "." or RemoteUrl contains "0" or RemoteUrl contains ":" or RemoteUrl contains "%" or RemoteUrl contains "http"
| where DeviceId != "1586d74a9f37323d27f7e29ec1a234324fsdöoldk"

```

</details>

<details>
<summary><strong>Port Scan from IP with Signed-In Users</strong><br><sub>Detects network scanning behavior and ties it back to signed-in users when available.</sub></summary>

<br>

**Source:** [`Portscanfromipusersignedin.kql`](./Portscanfromipusersignedin.kql)
**Tables:** `SigninLogs`, `_Im_NetworkSession`
**Use case:** Network investigation / IP and scanning triage

```kusto
// Port scan detection correlated with successful sign-ins using ASIM Network Session data.
// Tunables:
// - PortScanThreshold: minimum distinct destination ports per source IP in the time bin.
// - lookback: detection window.
// - trustedAzureRange: exclude known Azure source range noise from this environment.
let PortScanThreshold = 100;
let lookback = 1d;
let trustedAzureRange = "20.82.0.0/17";
// Successful sign-ins grouped by source IP so the join stays small and stable.
let SuccessfulSignins =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0
    | summarize
        SigninTime = max(TimeGenerated),
        Users = make_set(UserPrincipalName, 20),
        Apps = make_set(AppDisplayName, 20),
        RiskLevels = make_set(RiskLevel, 20),
        RiskStates = make_set(RiskState, 20)
      by IPAddress;
// ASIM Network Session is the generic normalized source for firewall/proxy/router-like network logs.
// If your workspace uses deployed parsers, the equivalent may be `imNetworkSession`.
let PortScanActivity =
    _Im_NetworkSession
    | where TimeGenerated > ago(lookback)
    | where isnotempty(SrcIpAddr)
    | where DstPortNumber > 0
    | where SrcIpAddr !in ("127.0.0.1", "::1")
    | where not(ipv4_is_in_range(SrcIpAddr, trustedAzureRange)) // Exclude trusted Azure source IP space.
    | where not(
        ipv4_is_match("10.0.0.0", SrcIpAddr, 8)
        or ipv4_is_match("172.16.0.0", SrcIpAddr, 12)
        or ipv4_is_match("192.168.0.0", SrcIpAddr, 16)
      ) // Exclude RFC1918 source IPs.
    | summarize
        DistinctDstPorts = dcount(DstPortNumber),
        PortSamples = make_set(DstPortNumber, 20),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
      by SrcIpAddr, bin(TimeGenerated, 5m)
    | where DistinctDstPorts > PortScanThreshold;
PortScanActivity
| join kind=inner SuccessfulSignins on $left.SrcIpAddr == $right.IPAddress
| project
    TimeGenerated = LastSeen,
    SrcIpAddr,
    DistinctDstPorts,
    PortSamples,
    FirstSeen,
    LastSeen,
    SigninTime,
    Users,
    Apps,
    RiskLevels,
    RiskStates,
    IPAddress
| order by DistinctDstPorts desc

```

</details>

### Defender

<details>
<summary><strong>Defender Service Tampering</strong><br><sub>Surfaces attempts to stop, disable, or remove Windows Defender services.</sub></summary>

<br>

**Source:** [`defenderservicetampering`](./defenderservicetampering)
**Tables:** `DeviceProcessEvents`
**Use case:** Defender / endpoint protection triage

```kusto
let includeProc = dynamic(["sc.exe","net1.exe","net.exe", "taskkill.exe", "cmd.exe", "powershell.exe"]);
let action = dynamic(["stop","disable", "delete"]);
let service1 = dynamic(['sense', 'windefend', 'mssecflt']);
let service2 = dynamic(['sense', 'windefend', 'mssecflt', 'healthservice']);
let params1 = dynamic(["-DisableRealtimeMonitoring", "-DisableBehaviorMonitoring" ,"-DisableIOAVProtection"]);
let params2 = dynamic(["sgrmbroker.exe", "mssense.exe"]);
let regparams1 = dynamic(['reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"', 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"']);
let regparams2 = dynamic(['ForceDefenderPassiveMode', 'DisableAntiSpyware']);
let regparams3 = dynamic(['sense', 'windefend']);
let regparams4 = dynamic(['demand', 'disabled']);
let timeframe = 1d;
 DeviceProcessEvents
  | where Timestamp >= ago(timeframe)
  | where InitiatingProcessFileName in~ (includeProc)
  | where (InitiatingProcessCommandLine has_any(action) and InitiatingProcessCommandLine has_any (service2) and InitiatingProcessParentFileName != 'cscript.exe')
  or (InitiatingProcessCommandLine has_any (params1) and InitiatingProcessCommandLine has 'Set-MpPreference' and InitiatingProcessCommandLine has '$true') 
  or (InitiatingProcessCommandLine has_any (params2) and InitiatingProcessCommandLine has "/IM") 
  or (InitiatingProcessCommandLine has_any (regparams1) and InitiatingProcessCommandLine has_any (regparams2) and InitiatingProcessCommandLine has '/d 1') 
  or (InitiatingProcessCommandLine has_any("start") and InitiatingProcessCommandLine has "config" and InitiatingProcessCommandLine has_any (regparams3) and InitiatingProcessCommandLine has_any (regparams4))
  | extend Account = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName), Computer = DeviceName

```

</details>

<details>
<summary><strong>Detect AV Exclusions</strong><br><sub>Detects changes to Windows Defender exclusion paths and ASR exclusions.</sub></summary>

<br>

**Source:** [`detectavexclutions.kql`](./detectavexclutions.kql)
**Tables:** `DeviceRegistryEvents`
**Use case:** Defender / endpoint protection triage

```kusto
DeviceRegistryEvents 
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where DeviceId != "1586d74a9f37323d27f7e29ec1a370df6b813191"
| where RegistryKey startswith ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions") or RegistryKey startswith ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\ASROnlyExclusions")
| project Timestamp, DeviceId, DeviceName, ExcludedFromDefender=RegistryValueName, ReportId

```

</details>

<details>
<summary><strong>Detect Disable Realtime Monitoring</strong><br><sub>Detects Windows Defender realtime monitoring being disabled.</sub></summary>

<br>

**Source:** [`detectDisableRealtimeMonitoring.kql`](./detectDisableRealtimeMonitoring.kql)
**Tables:** `DeviceRegistryEvents`
**Use case:** Defender / endpoint protection triage

```kusto
DeviceRegistryEvents
| where Timestamp > ago(10h)
| where RegistryValueName == "DisableRealtimeMonitoring"
| where RegistryValueData == "1"
| where DeviceId != "1586d74a9f37323d27f7e29ec1a370df6b813191"

```

</details>

<details>
<summary><strong>Detect Firewall Bypass</strong><br><sub>Surfaces firewall-disabling commands, registry changes, and PowerShell activity.</sub></summary>

<br>

**Source:** [`detectfwbypass.kql`](./detectfwbypass.kql)
**Tables:** `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceEvents`
**Use case:** Defender / endpoint protection triage

```kusto
let powershellCommandName = "Set-NetFirewallProfile"; 
let firewallbyps = (
DeviceEvents 
| where ActionType == "PowerShellCommand" 
| where AdditionalFields contains powershellCommandName
| where isnotempty(AdditionalFields)
);
let firewallbyregevent = (
DeviceRegistryEvents
| where RegistryValueName == "EnableFirewall"
| where RegistryValueData == "0"
);
let firewallbycmd = (
DeviceProcessEvents
| where FileName in~ ("net.exe", "net1.exe")
| extend CanonicalCommandLine=replace("\"", "", ProcessCommandLine)
| where CanonicalCommandLine contains "stop" and CanonicalCommandLine contains "MpsSvc"
);
let firewallbypsh = (
DeviceProcessEvents 
| where (((FolderPath endswith @'\powershell.exe' or FolderPath endswith @'\pwsh.exe' or FolderPath endswith @'\powershell_ise.exe') or ProcessCommandLine =~ @'PowerShell.EXE' or InitiatingProcessCommandLine =~ @'PowerShell.EXE') and (ProcessCommandLine contains @'Set-NetFirewallProfile ' and ProcessCommandLine contains @' -Enabled ' and ProcessCommandLine contains @' False') and (ProcessCommandLine contains @' -All ' or ProcessCommandLine contains @'Public' or ProcessCommandLine contains @'Domain' or ProcessCommandLine contains @'Private')));
let firewallbypsh1 = (
DeviceProcessEvents | where ((ProcessCommandLine contains @'netsh' and ProcessCommandLine contains @'firewall' and ProcessCommandLine contains @'set' and ProcessCommandLine contains @'opmode' and ProcessCommandLine contains @'mode=disable') or (ProcessCommandLine contains @'netsh' and ProcessCommandLine contains @'advfirewall' and ProcessCommandLine contains @'set' and ProcessCommandLine contains @'state' and ProcessCommandLine contains @'off'))
);
union firewallbyregevent,firewallbyps,firewallbycmd,firewallbypsh,firewallbypsh1

```

</details>

<details>
<summary><strong>Detect Many AV Detections</strong><br><sub>Flags endpoints with unusually high counts of antivirus detections.</sub></summary>

<br>

**Source:** [`detectectmanyavdetections.kql`](./detectectmanyavdetections.kql)
**Tables:** `DeviceEvents`
**Use case:** Defender / endpoint protection triage

```kusto
DeviceEvents
| where Timestamp > ago(3h)
| where DeviceId != "1586d74a9f37323d27f7e29ec1a370df6b813191"
| where ActionType == "AntivirusDetection"
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 25

```

</details>

<details>
<summary><strong>Realtime Protection Off</strong><br><sub>Detects hosts where Windows Defender realtime protection is not active.</sub></summary>

<br>

**Source:** [`realtimeprotectionoff.kql`](./realtimeprotectionoff.kql)
**Tables:** `DeviceTvmSecureConfigurationAssessment`
**Use case:** Defender / endpoint protection triage

```kusto
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(1h)
| where ConfigurationId == 'scid-2012'
| where OSPlatform == "Windows10"
| extend
RealtimeProtection=iif(ConfigurationId == "scid-2012" and IsCompliant==1, 1, 0)
| summarize
ReportId=any(DeviceId),
Timestamp=any(Timestamp),
DeviceName=any(DeviceName),
Is_RealtimeProtection_active_on_Host=iif(max(RealtimeProtection) == 1, "Yes", "No")
by DeviceId
| where Is_RealtimeProtection_active_on_Host == "No"

```

</details>

### Azure

<details>
<summary><strong>Azure VM Run Command Execution With MDE Evidence</strong><br><sub>Correlates Azure VM Run Command activity with endpoint-side execution evidence.</sub></summary>

<br>

**Source:** [`Azure-VM-RunCommand-Execution-With-MDE-Evidence.kql`](./Azure-VM-RunCommand-Execution-With-MDE-Evidence.kql)
**Tables:** `DeviceProcessEvents`, `DeviceEvents`, `AzureActivity`
**Use case:** Azure control-plane investigation

```kusto
//
// Name: Azure-VM-RunCommand-Remote-Execution-With-Endpoint-Evidence.kql
//
// Purpose:
// Correlates Azure VM Run Command control-plane activity from AzureActivity
// with endpoint-side execution evidence from Microsoft Defender for Endpoint.
//
// Prerequisites:
// - AzureActivity logs must be ingested into the queried Log Analytics / Sentinel workspace.
// - Microsoft Defender for Endpoint Advanced Hunting tables must be available in the same query scope.
// - The target VMs must be onboarded to Microsoft Defender for Endpoint.
// - Device names in MDE must correlate to Azure VM names, at least by short hostname.
// - Endpoint telemetry must include DeviceProcessEvents.
// - Script content is only shown when available in DeviceEvents / AMSI / PowerShell telemetry.
// - AzureActivity normally shows who invoked Run Command and on which VM, but usually does not contain the submitted script body.
// - TimeGenerated is UTC. Adjust Lookback or query time range accordingly.
//
let Lookback = 14d;
let TimeWindow = 15m;
//
// Azure control-plane: only actual VM Run Command executions
//
let AzureRunCommand =
    AzureActivity
    | where TimeGenerated >= ago(Lookback)
    | where ResourceProviderValue =~ "MICROSOFT.COMPUTE"
    | where OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
        or tostring(parse_json(Authorization).action) =~ "Microsoft.Compute/virtualMachines/runCommand/action"
        or Properties has "Microsoft.Compute/virtualMachines/runCommand/action"
    | extend ParsedClaims = todynamic(Claims)
    | extend ParsedAuth = todynamic(Authorization)
    | extend ParsedProps = todynamic(Properties)
    | extend VMName = tolower(tostring(coalesce(
        ParsedProps.resource,
        split(_ResourceId, "/")[8]
    )))
    | extend CallerIdentity = tostring(coalesce(
        Caller,
        ParsedClaims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"],
        ParsedClaims["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"],
        ParsedClaims["appid"]
    ))
    | extend CallerObjectId = tostring(coalesce(
        ParsedClaims["http://schemas.microsoft.com/identity/claims/objectidentifier"],
        ParsedClaims["oid"]
    ))
    | extend AppId = tostring(coalesce(
        ParsedClaims["appid"],
        ParsedClaims["azp"]
    ))
    | extend AuthRole = tostring(ParsedAuth.evidence.role)
    | extend AuthScope = tostring(ParsedAuth.evidence.roleAssignmentScope)
    | project
        RunCommandTime = TimeGenerated,
        SubscriptionId,
        ResourceGroup,
        VMName,
        CallerIdentity,
        CallerObjectId,
        AppId,
        CallerIpAddress,
        ActivityStatusValue,
        ActivitySubstatusValue,
        AuthRole,
        AuthScope,
        CorrelationId,
        ResourceId = _ResourceId;
//
// Endpoint telemetry: PowerShell, RunCommandExtension, regsvr32, cmd, and AMSI script content
//
let EndpointCommandEvidence =
    union isfuzzy=true
    (
        DeviceProcessEvents
        | where TimeGenerated >= ago(Lookback)
        | extend DeviceShortName = tolower(tostring(split(DeviceName, ".")[0]))
        | where FileName in~ (
            "RunCommandExtension.exe",
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "regsvr32.exe"
        )
        or ProcessCommandLine has_any (
            "RunCommandExtension",
            "script0.ps1",
            "-ExecutionPolicy Unrestricted",
            "regsvr32",
            "Microsoft.CPlat.Core.RunCommandWindows"
        )
        or InitiatingProcessCommandLine has_any (
            "RunCommandExtension",
            "script0.ps1",
            "Microsoft.CPlat.Core.RunCommandWindows"
        )
        | project
            EvidenceTime = TimeGenerated,
            DeviceName,
            DeviceShortName,
            EvidenceType = "Process",
            EvidenceAction = ActionType,
            EvidenceFile = FileName,
            CommandOrScript = ProcessCommandLine,
            InitiatingProcessFileName,
            InitiatingProcessCommandLine,
            InitiatingProcessAccountName,
            ProcessId,
            InitiatingProcessId
    ),
    (
        DeviceEvents
        | where TimeGenerated >= ago(Lookback)
        | extend DeviceShortName = tolower(tostring(split(DeviceName, ".")[0]))
        | where ActionType has_any (
            "Amsi",
            "PowerShell",
            "Script"
        )
        or AdditionalFields has_any (
            "script0.ps1",
            "regsvr32",
            "fm20.dll",
            "mscomctl.ocx",
            "RunCommandExtension"
        )
        | extend AF = todynamic(AdditionalFields)
        | extend ScriptContent = tostring(coalesce(
            AF.ScriptContent,
            AF.Command,
            AF.CommandLine,
            AF.Content,
            AF.ScriptBlockText,
            AF.Payload
        ))
        | where isnotempty(ScriptContent)
            or AdditionalFields has_any (
                "script0.ps1",
                "regsvr32",
                "fm20.dll",
                "mscomctl.ocx",
                "RunCommandExtension"
            )
        | project
            EvidenceTime = TimeGenerated,
            DeviceName,
            DeviceShortName,
            EvidenceType = "DeviceEvent",
            EvidenceAction = ActionType,
            EvidenceFile = "",
            CommandOrScript = coalesce(ScriptContent, tostring(AdditionalFields)),
            InitiatingProcessFileName,
            InitiatingProcessCommandLine,
            InitiatingProcessAccountName,
            ProcessId = int(null),
            InitiatingProcessId = int(null)
    );
//
// Correlate Azure RunCommand with endpoint execution evidence on the target VM.
// Rows with missing endpoint evidence arrays are removed after summarization.
//
AzureRunCommand
| join kind=leftouter EndpointCommandEvidence on $left.VMName == $right.DeviceShortName
| where isempty(EvidenceTime)
    or EvidenceTime between ((RunCommandTime - TimeWindow) .. (RunCommandTime + TimeWindow))
| summarize
    FirstEndpointEvidence=min(EvidenceTime),
    LastEndpointEvidence=max(EvidenceTime),
    EndpointActions=make_set_if(EvidenceAction, isnotempty(EvidenceAction), 20),
    ProcessFiles=make_set_if(EvidenceFile, isnotempty(EvidenceFile), 20),
    CommandsOrScripts=make_set_if(CommandOrScript, isnotempty(CommandOrScript), 50),
    InitiatingProcesses=make_set_if(InitiatingProcessCommandLine, isnotempty(InitiatingProcessCommandLine), 30),
    LoggedOnOrProcessUsers=make_set_if(InitiatingProcessAccountName, isnotempty(InitiatingProcessAccountName), 20)
    by
    RunCommandTime,
    SubscriptionId,
    ResourceGroup,
    VMName,
    CallerIdentity,
    CallerObjectId,
    AppId,
    CallerIpAddress,
    ActivityStatusValue,
    ActivitySubstatusValue,
    AuthRole,
    AuthScope,
    CorrelationId,
    ResourceId
| where array_length(ProcessFiles) > 0
| where array_length(InitiatingProcesses) > 0
| where array_length(CommandsOrScripts) > 0
| where array_length(EndpointActions) > 0
| order by RunCommandTime desc

```

</details>

### Parser / Helper

<details>
<summary><strong>UAL Mail Items Accessed</strong><br><sub>Normalizes UAL data for downstream hunting and investigation.</sub></summary>

<br>

**Source:** [`UAL-MailsAccessed.kql`](./parser/UAL-MailsAccessed.kql)
**Tables:** `UAL`
**Use case:** Parsing / normalization helper

```kusto

let sessionids = dynamic([
"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" //change SessionIDS here
"yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
]);
UAL
| where Operation == "MailItemsAccessed"
| extend AuditData = parse_json(AuditData)
| where AuditData.AppAccessContext.AADSessionId in (sessionids)
| extend CreationTime = todatetime(AuditData.CreationTime),UserId = tostring(AuditData.UserId),ClientIP = tostring(AuditData.ClientIPAddress),SessionId = tostring(AuditData.AppAccessContext.AADSessionId)
| mv-expand Folder = AuditData.Folders
| mv-expand Item = Folder.FolderItems
| extend InternetMessageId = tostring(Item.InternetMessageId),Subject = tostring(Item.Subject),ItemCreationTime = todatetime(Item.CreationTime),SizeInBytes = tolong(Item.SizeInBytes),FolderPath = tostring(Folder.Path)
| where isnotempty(InternetMessageId)
| project TimeGenerated=CreationTime,ItemCreationTime,UserId,ClientIP,SessionId,FolderPath,InternetMessageId,Subject,SizeInBytes,RecordId
| summarize arg_min(TimeGenerated, *) by InternetMessageId

```

</details>

<details>
<summary><strong>UAL Sign-Ins</strong><br><sub>Normalizes UAL data for downstream hunting and investigation.</sub></summary>

<br>

**Source:** [`UAL-Signins.kql`](./parser/UAL-Signins.kql)
**Tables:** `UAL`
**Use case:** Parsing / normalization helper

```kusto
UAL
| where ['Operation'] in ("UserLoggedIn","UserLoginFailed","Authorize")
| extend AuditData = parse_json(AuditData)
| extend 
CreationTime = todatetime(AuditData.CreationTime),
Operation = tostring(AuditData.Operation),
OrganizationId = tostring(AuditData.OrganizationId),
RecordType = toint(AuditData.RecordType),
UserId = tostring(AuditData.UserId),
UserKey = tostring(AuditData.UserKey),UserType = toint(AuditData.UserType),
Workload = tostring(AuditData.Workload),
ResultStatus = tostring(AuditData.ResultStatus),
ClientIP = tostring(AuditData.ClientIP),
ActorIpAddress = tostring(AuditData.ActorIpAddress),
AppId = coalesce(tostring(AuditData.ApplicationId),
tostring(AuditData.AadAppId)),
ObjectId = tostring(AuditData.ObjectId),
ErrorCode = tostring(AuditData.ErrorNumber),
LogonError = tostring(AuditData.LogonError)
| extend IP = coalesce(ClientIP,ActorIpAddress)
| mv-apply ep = AuditData.ExtendedProperties on (
    summarize ResultStatusDetail = anyif(tostring(ep.Value), tostring(ep.Name)=="ResultStatusDetail"),UserAgent = anyif(tostring(ep.Value), tostring(ep.Name)=="UserAgent"),RequestType = anyif(tostring(ep.Value), tostring(ep.Name)=="RequestType")
)
| mv-apply dp = AuditData.DeviceProperties on (
    summarize Browser = anyif(tostring(dp.Value), tostring(dp.Name)=="BrowserType"),OS = anyif(tostring(dp.Value), tostring(dp.Name)=="OS"),IsCompliant = anyif(tostring(dp.Value), tostring(dp.Name)=="IsCompliant"),IsManaged = anyif(tostring(dp.Value), tostring(dp.Name)=="IsCompliantAndManaged"),SessionId = anyif(tostring(dp.Value), tostring(dp.Name)=="SessionId")
)
| extend SignInResult = case(Operation=="UserLoginFailed","Failure",ResultStatus =~ "Success","Success","Other"),AuthFlow = case(Operation=="Authorize","Token/Authorize",RequestType has "OAuth2","OAuth2",RequestType has "Login","Interactive","Other")
| project TimeGenerated=CreationTime,Operation,UserId,IP,SignInResult,ResultStatus,ResultStatusDetail,AuthFlow,RequestType,UserAgent,AppId,ObjectId,Workload,OS,Browser,SessionId,IsCompliant,IsManaged,ErrorCode,LogonError,RecordId
| where Operation == "Authorize"

```

</details>

<!-- END GENERATED KQL CATALOG -->

## Structure

- Root `.kql` files cover the main hunts and detections
- `parser/` contains UAL parsing helpers

## Use

Open a query, swap in your entity or IP, adjust the time window, and run it in your hunting workspace.

## Maintenance

- The query catalog is generated from the repository's query files and should not be edited manually.
- Regenerate it after changing any `.kql` or KQL-like query file with `python3 scripts/generate-readme-catalog.py`.
- Review the result with `git diff README.md` before committing.
