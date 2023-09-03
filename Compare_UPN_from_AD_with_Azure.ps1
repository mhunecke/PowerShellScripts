<#
.Synopsis
    Script to compare the UPN from OnPremises Active Directory with Azure AD.
.DESCRIPTION
    Script to compare the UPN from OnPremises Active Directory with Azure AD.

    Disclaimer:
    ===========
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production
    environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
    EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR
    FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free right to use and modify the Sample
    Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded;
    (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
    (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits,
    including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.

    This sample script is not supported under any Microsoft standard support program or service. The sample script is
    provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without
    limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk
    arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall
    Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable
    for any damages whatsoever (including, without limitation, damages for loss of business profits, business
    interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use
    the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.

    FileName:       .\Compare_UPN_from_AD_with_Azure.ps1
    Author:         Marcelo Hunecke - Microsoft (mhunecke@microsoft.com)
    Creation date:  Aug 10th, 2023
    Last update:    Sep 09th, 2023
    Version:        1.50a

    Changelog:
    ==========
    1.50 - Aug 23th, 2023
        - Added the option to use the mail attribute as Alternative Logon ID.
        - Ignore users with adminDescription attribute filled.
        - Do not required to connecting to Microsoft Graph anymore (speed up the script).
    1.50a - Sep 24th, 2023
        - Ignore the users located in OU that are configured to do not sync with Office 365.
        - Rename the script to Compare_UPN_from_AD_with_Azure.ps1
        - Change some variable names, just for standardization
#>

#log files variables
$DateTime = Get-Date -Format yyyy_M_d@HH_mm_ss
$RunOnPremises = "Compare_UPN_from_AD_with_Azure_RunOnPremises_" + $DateTime + ".txt"
$RunOnCloud = "Compare_UPN_from_AD_with_Azure_RunOnCloud_" + $DateTime + ".txt"
$logName = "Compare_UPN_from_AD_with_Azure_ExecutionLog_" +  $DateTime + ".txt"
#Your environment variables 
$DomainToReplace = "contoso.com" #Replace the <contoso.com> string by your desired domain (must be a Microsoft 365 accepted domain).
$AlternativeLogonID_Atribute = "UserPrincipalName" #Attribute to be used as Alternative Logon ID (mail or userPrincipalName). If you don't know about Alternative Logon ID, maybe you ar not using. So, leave it as UserPrincipalName.

#---------------------------------------------------------------------
# Write the log
#---------------------------------------------------------------------
Function log{
    Param(
        [string]$Status,
        [string]$Message
    )
    
    $dayLogFile = Test-Path $logName
    $dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss
    If($dayLogFile -eq $true)
        {
        $logLine = $dateTime + "," + $Status + "," + $Message
        $logLine | Out-File -FilePath $logName -Append
        }
    Else
        {
        $header = "DateTime,Status,Message"
        $header | Out-File -FilePath $logName
        $logLine = $dateTime + "," + $Status + "," + $Message
        $logLine | Out-File -FilePath $logName -Append
        }
}
#---------------------------------------------------------------------
# Connect to AzureAD
#---------------------------------------------------------------------
function ConnectAzureAD
{
    try 
        {
            Write-Debug "Get-AzureADDirectoryRole -ErrorAction stop"
            $testConnection = Get-AzureADDirectoryRole -ErrorAction stop | Out-Null #if true (Already Connected)
            Write-Host "You are already connected to Microsoft Azure AD."
            log -Status "INFORMATION" -Message "You are already connected to Microsoft Azure AD."
        }
        catch
            {
                try
                    {
                        write-Debug $error[0].Exception
                        Write-Host "Connecting to Microsoft Azure AD..."
                        Connect-AzureAD -WarningAction SilentlyContinue -ErrorAction stop | Out-Null
                        log -Status "INFORMATION" -Message "Connecting to Microsoft Azure AD..."
                    }
                    catch    
                        {
                            try
                                {
                                    write-Debug $error[0].Exception
                                    Write-Host "Installing Microsoft Azure AD PowerShell Module..."
                                    log -Status "INFORMATION" -Message "Installing Microsoft Azure AD PowerShell Module..."
                                    Install-Module AzureAD -Force -AllowClobber
                                    Connect-AzureAD -WarningAction SilentlyContinue -ErrorAction stop | Out-Null
                                }
                                catch
                                    {
                                        write-Debug $error[0].Exception
                                        Write-Host "Couldn't connect to Microsoft Azure AD. Exiting."
                                        log -Status "Error" -Message "Couldn't connect to Microsoft AD. Exiting."
                                        Exit
                                    }
                       
                        }
            }
}

#---------------------------------------------------------------------
# Connect to Microsoft Online
#---------------------------------------------------------------------
function ConnectMsol
{
    try 
        {
            Write-Debug "Get-MSOLCompanyInformation -ErrorAction stop"
            $testConnection = Get-MSOLCompanyInformation -ErrorAction stop | Out-Null #if true (Already Connected)
            Write-Host "You are already connected to Microsoft Online..."
            log -Status "INFORMATION" -Message "You are already connected to Microsoft Online."
        }
        catch
            {
                try
                    {
                        write-Debug $error[0].Exception
                        Write-Host "Connecting to Microsoft Online..."
                        log -Status "INFORMATION" -Message "Connecting to Microsoft Online."
                        Connect-MSOLService -ErrorAction stop | Out-Null
                    }
                    catch    
                        {
                            try
                                {
                                    write-Debug $error[0].Exception
                                    Write-Host "Installing Microsoft Online PowerShell Module..."
                                    log -Status "INFORMATION" -Message Write-Host "Installing Microsoft Online PowerShell Module..."
                                    Install-Module MSOnline -Force -AllowClobber -ErrorAction stop | Out-Null
                                    Connect-MSOLService -ErrorAction stop | Out-Null
                                }
                                catch
                                    {
                                        write-Debug $error[0].Exception
                                        Write-Host "Couldn't connect to  Microsoft Online. Exiting."
                                        log -Status "Error" -Message "Couldn't connect to  Microsoft Online. Exiting."
                                        exit
                                    }
                    
                        }
            }
}

#---------------------------------------------------------------------
# Script start here
#---------------------------------------------------------------------

Clear-Host
#[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
#[Net.ServicePointManager]::SecurityProtocol
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss;Write-Host $dateTime
log -Status "INFORMATION" -Message "..:: STARTED ::.."

ConnectAzureAD
ConnectMsol

$TotalUsersCounter = 0
$UsersToChangeCounter = 0
"# Run these cmdlets on OnPremises Active Directory PowerShell" | out-file $RunOnPremises
"# IMPORTANT: Replace the <contoso.com> string by your desired domain (must be a Microsoft 365 accepted domain)" | out-file -append $RunOnPremises
"#---------------------------------------------------------------------------" | out-file -append $RunOnPremises
"# Run these cmdlets on Microsoft Online PowerShell | Connect-MSOL" | out-file $RunOnCloud
"#---------------------------------------------------------------------------" | out-file -append $RunOnCloud
Write-Host "Reading OnPremises Active Directory Users...."
log -Status "INFORMATION" -Message "Reading OnPremises Active Directory Users...."
#$FQDN_DC = "dc01.contoso.net" #FQDN of the OnPremises Active Directory Domain Controller
#$Domain_OU_DN = "DC=contoso,DC=net" #OU Distinguished Name of the OnPremises Active Directory Domain
#$allADusers = Get-ADUser -filter * -SearchBase $Domain_OU_DN -Server $FQDN_DC -Properties Mail, DisplayName, UserPrincipalName, objectSid, adminDescription | where-object {$_.mail -ne $null -and $_.adminDescription -eq $null} | select-object DisplayName, UserPrincipalName, objectSid, Mail
$allADusers = Get-ADUser -filter * -Properties Mail, DisplayName, UserPrincipalName, objectSid, distinguishedName, adminDescription | where-object {$_.mail -ne $null -and $_.adminDescription -eq $null} | select-object Mail, DisplayName, UserPrincipalName, objectSid, distinguishedName
$allADusersCount = $allADusers.count

$AzureADDomains = Get-AzureADDomain | select-object Name
foreach ($allADuser in $allADusers)
    {
        $TotalUsersCounter++
        $PercentComplete = ($TotalUsersCounter / $allADusersCount) * 100
        Write-Progress -Activity 'Reading user attributes...' -Status "$TotalUsersCounter users of $allADusersCount users already checked." -PercentComplete $PercentComplete

        $allADuser_Mail = $allADuser.Mail
        $allADuser_DisplayName = $allADuser.DisplayName
        $allADuser_UPN = $allADuser.UserPrincipalName
        $allADuser_Sid = $allADuser.ObjectSid.value
        $allADuser_DN = $allADuser.DistinguishedName
        
       
        If ($AlternativeLogonID_Atribute -eq "UserprincipalName")
            {
                $allADuser_CompareAttribute = $allADuser_UPN
                $attributeNameString = "UserPrincipalName ---> "
                $attributeNameCmdlet = "UserPrincipalName"
            }
            else
                {
                    $allADuser_CompareAttribute = $allADuser_Mail
                    $attributeNameString = "Mail ----------------> "
                    $attributeNameCmdlet = "Mail"
                }

        Try
            {
                $allAzureuser = Get-AzureADUser -Filter "OnPremisesSecurityIdentifier eq '$allADuser_Sid'" | select-object UserPrincipalName, ObjectID, OnPremisesSecurityIdentifier #-ErrorAction Stop
                $allAzureuser_UPN = $allAzureuser.userprincipalname

                if ($allAzureuser_UPN -ne $allADuser_CompareAttribute -and $null -ne $allAzureuser_UPN)
                    {
                        $UsersToChangeCounter++
                        Write-Host
                        Write-Host "#", $UsersToChangeCounter
                        Write-Host "Display Name ----------------------> ", $allADuser_DisplayName -ForegroundColor Cyan
                        Write-Host "Azure AD UserPrincipalName --------> ", $allAzureuser_UPN -ForegroundColor Cyan
                        Write-Host "OnPremises AD", $attributeNameString, $allADuser_CompareAttribute -ForegroundColor Cyan
                        Write-Host "OnPremises AD DistinguishedName ---> ", $allADuser_DN -ForegroundColor Cyan

                        log -Status "INFORMATION" -Message ""
                        log -Status "INFORMATION" -Message "#", $UsersToChangeCounter
                        log -Status "INFORMATION" -Message "Display Name ----------------------> ", $allADuser_DisplayName
                        log -Status "INFORMATION" -Message "Azure AD UPN ----------------------> ", $allAzureuser_UPN
                        log -Status "INFORMATION" -Message "OnPremises AD", $attributeNameString, $allADuser_CompareAttribute
                        log -Status "INFORMATION" -Message "OnPremises AD DistinguishedName ---> ", $allADuser_DN

                        $isAcceptedDomain = $False
                        foreach ($AzureADDomain in $AzureADDomains)
                            {
                                $AzureADDomain_Name = $AzureADDomain.Name
                                if ($allADuser_CompareAttribute -like "*$AzureADDomain_Name")
                                    {
                                        $isAcceptedDomain = $True
                                    }
                            }

                        if ($isAcceptedDomain -eq $False)
                            {
                                $NewUPN = $allADuser_UPN.split("@")[0] + "@" + $DomainToReplace
                                Write-Host "Action: Run the the following cmdlet on OnPremises Active Directory Powershell:" -ForegroundColor Yellow
                                Write-Host  "Set-Aduser -identity", $allADuser_Sid, "-",$attributeNameCmdlet, $NewUPN
                                "#Changing the user " + $attributeNameCmdlet + " from " + $allADuser_UPN + " to " + $NewUPN | out-file -append $RunOnPremises
                                "Set-Aduser -identity " + $allADuser_Sid + " -" + $attributeNameCmdlet + " " + $NewUPN | out-file -append $RunOnPremises

                                log -Status "INFORMATION" -Message "Action: Run the the following cmdlet on OnPremises Active Directory Powershell:"
                                log -Status "INFORMATION" -Message "#Changing the user", $attributeNameCmdlet + "from" + $allADuser_UPN + "to" + $NewUPN
                                log -Status "INFORMATION" -Message "Set-Aduser -identity", $allADuser_Sid, "-",$attributeNameCmdlet, $NewUPN

                            }
                            else
                                {
                                    Write-Host "Action: Run the the following cmdlet on Microsoft Online (MSOL) Powershell:" -ForegroundColor Yellow
                                    Write-Host "Set-MsolUserPrincipalName -UserPrincipalName", $allAzureuser_UPN, "-NewUserPrincipalName", $allADuser_CompareAttribute
                                    "Set-MsolUserPrincipalName -UserPrincipalName " + $allAzureuser_UPN + " -NewUserPrincipalName " + $allADuser_CompareAttribute | out-file -append $RunOnCloud

                                    log -Status "INFORMATION" -Message "Action: Run the the following cmdlet on Microsoft Online (MSOL) Powershell:"
                                    log -Status "INFORMATION" -Message "Set-MsolUserPrincipalName -UserPrincipalName", $allAzureuser_UPN, "-NewUserPrincipalName", $allADuser_CompareAttribute
                                }
                    }
            }
            catch
                {
                }
    }
Write-Host
Write-Host "Script finished successfully !!" -ForegroundColor Yellow
log -Status "INFORMATION" -Message ""
log -Status "INFORMATION" -Message "Script finished successfully !!"
log -Status "INFORMATION" -Message "..:: COMPLETED ::.."
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss
Write-Host $dateTime