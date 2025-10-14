# Filename: lab-finance_preparation_unconstrained-delegation.md

# Preparing LAB-FINANCE - Unconstrained delegation & SMB signing steps

## 0. Install vulnerable app on LAB-FINANCE
- Install Wise Care (used later for local privilege escalation).  
- Reference: https://www.exploit-db.com/exploits/50038

## 1. Disable SMB signing on each client (local policy)
- Run `gpedit.msc` on each client:
  - Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
  - Set these to **Disabled**:
    - Microsoft network client: Digitally sign communications (always)
    - Microsoft network server: Digitally sign communications (always)

- Registry alternative (run as admin):
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"    -Name "RequireSecuritySignature" -Value 0 -Type DWord
# restart SMB services or reboot as needed
```

## 2. Enable unconstrained delegation for LAB-FINANCE (on LAB-DC)
Note: Unconstrained delegation causes the host to cache TGTs for users that authenticate to it. 

- Set-ADComputer -Identity "LAB-FINANCE" -TrustedForDelegation $true
#### TO CHECK ####
- Get-ADComputer -Identity "LAB-FINANCE" -Properties TrustedForDelegation | Select-Object Name, TrustedForDelegation



