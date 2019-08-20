<#
 .SYNOPSIS
 This script will automate the creation of a Group Managed Service Account,
 install the account locally, produce the JSON file with gMSA info, and convert
 it to the Yaml file needed.

 .NOTES
 This is only for automated e2e testing.  DO NOT use this for production.
 Jeremy Wood (JeremyWx)
 Version: 1.0.0.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

#Function to check AD services
function CheckADServices()
	{
	Sleep 4
	$svcs = "adws","dns","kdc","netlogon","ntds","lanmanserver","lanmanworkstation"
    $svcstatus = 0
        foreach ( $svc in $svcs ) {
            if ( $(Get-Service -Name $svc).Status -notlike "Running") {
                $svcstatus += 1
            }
        }

	if ($svcstatus -gt 0) {
		return $false
		} else {
		return $true
		}
	}


# Change to working directory
Set-Location -Path C:\gmsa

# Script Logging - Feel free to comment out if you like.
Start-Transcript -Path "C:\gmsa\Setup-gmsa.txt" -Append
# Making sure the AD services are up and running

do {$result = CheckADServices} while ($result -eq $false)
Import-Module ActiveDirectory

if (Get-AdGroupMember -Identity "Enterprise Admins" | Select-String -Pattern "gmsa-admin" -Quiet) {
    
	# Add the KDS Root Key
    $KdsRootKey = Get-KdsRootKey
    if ($KdsRootKey -eq $null) {
		# This command creates the KDS Root Key with a time 10 hours in the past.
		# Active Directory will not premit use of this key until at least 10 hours has
		# passed to allow distribution to all Domain Controllers in the domain.
		# https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key
        Add-KdsRootKey –EffectiveTime ((get-date).addhours(-10))
		# Make sure we are PAST the 10 hour mark
        Start-Sleep -Seconds 15
    }
    
    # Directory for credspecs if not already created
    mkdir -Path C:\ProgramData\docker\credentialspecs -ErrorAction SilentlyContinue

    # Get GenerateCredSpecResource PowerShell Module
    Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/kubernetes-sigs/windows-gmsa/master/scripts/GenerateCredentialSpecResource.ps1 -OutFile GenerateCredentialSpecResource.ps1

    # Import AD Module and Setup gMSA
    New-ADServiceAccount -Name gmsa-e2e -DNSHostName gmsa-e2e.k8sgmsa.lan -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers" -ServicePrincipalnames http/gmsa-e2e.k8sgmsa.lan

    # Run GenerateCredSpecResource to provide the Yaml CredSpec
    C:\gmsa\GenerateCredentialSpecResource.ps1 gmsa-e2e gmsa-e2e

} else {
    # Add new admin account to needed groups
    Add-ADGroupMember -Identity "Enterprise Admins" -Members gmsa-admin
    Add-ADGroupMember -Identity "Domain Admins" -Members gmsa-admin
    $RunOnce = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $RunOnce "gmsa" -Value "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -command C:\gmsa\Setup-gMSA.ps1" -Type String
    Restart-Computer -Force
}

