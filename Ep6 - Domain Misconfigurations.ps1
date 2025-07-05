<#
.SYNOPSIS
Creates lab user accounts for various Active Directory attack techniques:
- AS-REP Roasting
- Kerberoasting
- DACL abuse
- ESC1 certificate abuse
- Local admin testing

.REQUIREMENTS
- Active Directory module must be available
- Script should be run as a Domain Admin on LAB-DC
#>

Import-Module ActiveDirectory

Write-Host "`n[+] Starting lab user creation..." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────
# 1️⃣ AS-REP Roasting User: asrep_user (No PreAuth)
# ─────────────────────────────────────────────────────────────

Write-Host "[*] Creating AS-REP Roasting user: 'asrep_user'" -ForegroundColor Yellow

New-ADUser -Name "asrep_user" -SamAccountName "asrep_user" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd1!" -AsPlainText -Force) `
  -Enabled $true

# Disable Kerberos pre-authentication
$user = Get-ADUser asrep_user -Properties userAccountControl
Set-ADUser asrep_user -Replace @{userAccountControl = ($user.userAccountControl -bor 4194304)}

Write-Host "[+] 'asrep_user' created with DONT_REQ_PREAUTH flag set." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 2️⃣ Kerberoasting User: svc_sql (With SPN)
# ─────────────────────────────────────────────────────────────

Write-Host "`n[*] Creating Kerberoasting user: 'svc_sql'" -ForegroundColor Yellow

New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
  -UserPrincipalName "svc_sql@pentest.local" `
  -Description "Password = WeakPass1" `
  -AccountPassword (ConvertTo-SecureString "WeakPass1" -AsPlainText -Force) `
  -Enabled $true

Set-ADUser svc_sql -ServicePrincipalNames @{Add="MSSQLSvc/lab-media.pentest.local:1433"}

Write-Host "[+] 'svc_sql' created with SPN bound for Kerberoasting." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 3️⃣ DACL Abuse User: dacl_user → GenericAll over Domain Admins
# ─────────────────────────────────────────────────────────────

Write-Host "`n[*] Creating 'dacl_user' and assigning GenericAll on Domain Admins..." -ForegroundColor Yellow

New-ADUser -Name "dacl_user" -SamAccountName "dacl_user" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd2!" -AsPlainText -Force) `
  -Enabled $true

# Grant DACL rights
$daclUser = Get-ADUser dacl_user
$sid = New-Object System.Security.Principal.SecurityIdentifier($daclUser.SID)
$domainDN = (Get-ADDomain).DistinguishedName

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=group)(cn=Domain Admins))"
$searcher.SearchRoot = "LDAP://$domainDN"
$searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
$searcher.PropertiesToLoad.Add("ntSecurityDescriptor") | Out-Null
$searcher.SearchScope = "Subtree"
$searcher.PageSize = 1

$result = $searcher.FindOne()
$daDN = $result.Properties["distinguishedName"][0]
$daGroup = [ADSI]("LDAP://$daDN")
$sd = $daGroup.ObjectSecurity

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule (
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$sd.AddAccessRule($ace)
$daGroup.ObjectSecurity = $sd
$daGroup.CommitChanges()

Write-Host "[+] 'dacl_user' now has GenericAll over Domain Admins group." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 4️⃣ ESC1 Abuse User: cert_user (for certificate template abuse)
# ─────────────────────────────────────────────────────────────

Write-Host "`n[*] Creating ESC1 abuse user: 'cert_user'" -ForegroundColor Yellow

New-ADUser -Name "cert_user" -SamAccountName "cert_user" `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd3!" -AsPlainText -Force) `
  -Enabled $true

Write-Host "[+] 'cert_user' created." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 5️⃣ Local Admin Account: local_admin (for client systems)
# ─────────────────────────────────────────────────────────────

Write-Host "`n[*] Creating local admin account: 'local_admin'" -ForegroundColor Yellow

New-ADUser -Name "local_admin" -SamAccountName "local_admin" `
  -UserPrincipalName "local_admin@pentest.local" `
  -AccountPassword (ConvertTo-SecureString "Adm1nLocal!" -AsPlainText -Force) `
  -Enabled $true

Write-Host "[+] 'local_admin' created. Assign this user to local Administrators on client machines as needed." -ForegroundColor Green

# ─────────────────────────────────────────────────────────────

Write-Host "`n[✓] All lab users created successfully." -ForegroundColor Cyan
