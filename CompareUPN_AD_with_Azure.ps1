<#
.Synopsis
    Script to compare the UPN from Azure AD and OnPremises AD
.DESCRIPTION
    Script to compare the UPN from Azure AD and OnPremises AD

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

    FileName:       .\CompareUPNs.ps1
    Author:         Marcelo Hunecke - Customer Engineer
    Creation date:  Aug 3rd, 2023
    last update:    Aug 16th, 2023
    Version:        1.3

#>

$DateTime = Get-Date -Format yyyy_M_d@HH_mm_ss
$NeedToChangeOnPremiseUPN = "CompareUPN_AD_with_Azure_NeedToChangeOnPremiseUPN_" + $DateTime + ".txt"
$NeedToRunPowerShell = "CompareUPN_AD_with_Azure_NeedToRunPowerShell_" + $DateTime + ".txt"
$logName = "CompareUPN_Log_" +  $DateTime + ".txt"
$DomainToReplace = "contoso.com"
#also update line 205

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
            Write-Host "You are now connected to Microsoft Azure AD..."
            log -Status "INFORMATION" -Message "You are now connected to Microsoft Azure AD..."
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
                                        write-host "Couldn't connect to Microsoft Azure AD. Exiting."
                                        log -Status "Error" -Message "Couldn't connect to Microsoft AD. Exiting."
                                        Exit
                                    }
                       
                        }
            }
}

#---------------------------------------------------------------------
# Connect to MSGraph
#---------------------------------------------------------------------
function ConnectMSGraph
{
    try 
        {
            Write-Debug "Get-MgUser -ErrorAction stop"
            $testConnection = Get-MgUser -ErrorAction stop | Out-Null #if true (Already Connected)
            Write-Host "You are now connected to Microsoft Graph..."
            log -Status "INFORMATION" -Message "You are now connected to Microsoft Graph..."
        }
        catch
            {
                try
                    {
                        write-Debug $error[0].Exception
                        Write-Host "Connecting to Microsoft Graph..."
                        log -Status "INFORMATION" -Message "Connecting to Microsoft Graph..."
                        Connect-Graph -Scopes "User.Read.All" -ErrorAction stop | Out-Null
                    }
                    catch    
                        {
                            try
                                {
                                    write-Debug $error[0].Exception
                                    Write-Host "Installing Microsoft Graph PowerShell Module..."
                                    log -Status "INFORMATION" -Message "Installing Microsoft Graph PowerShell Module..."
                                    Install-Module Microsoft.Graph -Force -AllowClobber
                                    Connect-Graph -Scopes "User.Read.All" -ErrorAction stop | Out-Null
                                }
                                catch
                                    {
                                        write-Debug $error[0].Exception
                                        Write-Host "Couldn't connect to Microosft Graph. Exiting."
                                        log -Status "Error" -Message "Couldn't connect to Microosft Graph. Exiting."
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
            Write-Host "You are now connected to Microsoft Online..."
            log -Status "INFORMATION" -Message "You are now connected to Microsoft Online..."
        }
        catch
            {
                try
                    {
                        write-Debug $error[0].Exception
                        Write-Host "Connecting to Microsoft Online..."
                        log -Status "INFORMATION" -Message "Connecting to Microsoft Online..."
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

Clear-Host
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss;Write-Host $dateTime
log -Status "INFORMATION" -Message "..:: STARTED ::.."

$UserCounter = 0
"Run these cmlets on Active Directory PowerShell" | out-file $NeedToChangeOnPremiseUPN
"Run these cmlets on Microsoft Online PowerShell | Connect-MSOL" | out-file $NeedToRunPowerShell
write-host "Reading Active Directory Users...."
log -Status "INFORMATION" -Message "Reading Active Directory Users...."
$allADusers = Get-ADUser -filter * -SearchBase 'DC=contoso,DC=com' -Properties Mail, DisplayName | where-object {$_.mail -ne $null} | select-object DisplayName, DistinguishedName, UserPrincipalName, objectGUID
$allADusersCount = $allADusers.count

ConnectAzureAD
ConnectMSGraph
ConnectMsol

$AzureADDomains = Get-AzureADDomain | select-object Name
foreach ($allADuser in $allADusers)
    {
        $UserCounter++
        $PercentComplete = ($UserCounter / $allADusersCount) * 100
        Write-Progress -Activity 'Reading user attributes...' -Status "$UserCounter users of $allADusersCount users already checked." -PercentComplete $PercentComplete
        Try
            {
                $allADuser_UPN = $allADuser.UserPrincipalName
                #$allADuser_DN = $allADuser.DistinguishedName
                $allADuser_GUID = $allADuser.objectGUID
                $allADuser_ImmutableID = [system.convert]::ToBase64String(([GUID]$allADuser_GUID).ToByteArray())
                $allADuser_DisplayName = $allADuser.DisplayName
                #Write-Host $allADuser_UPN
                #Write-Host $allADuser_DN
                #Write-Host $allADuser_ImmutableID
                #Write-Host $allADuser_DisplayName
                
                $allAzureuser = Get-AzureADUser -Filter "immutableid eq '$allADuser_ImmutableID'" | select-object UserPrincipalName, ObjectID #-ErrorAction Stop
                $allAzureuser_UPN = $allAzureuser.userprincipalname
                $allAzureuser_ObjectID = $allAzureuser.ObjectID
                #Write-host $allAzureuser_UPN -ForegroundColor Green
                #Write-host $allAzureuser_ObjectID -ForegroundColor Green

                $allGraphsuser = Get-MgUser -UserId $allAzureuser_ObjectID -Property OnPremisesUserPrincipalName | select-object OnPremisesUserPrincipalName -ErrorAction Stop
                $allGraphsuser_UPN = $allGraphsuser.OnPremisesUserPrincipalName
                #Write-host $allGraphsuser_UPN -ForegroundColor Yellow

                if ($allAzureuser_UPN -ne $allGraphsuser_UPN)
                    {
                        write-host
                        write-host "Display Name ---------------> ", $allADuser_DisplayName -ForegroundColor Cyan
                        Write-host "Azure AD current UPN -------> ", $allAzureuser_UPN -ForegroundColor Cyan
                        Write-host "Azure AD OnPremises UPN ----> ", $allGraphsuser_UPN -ForegroundColor Cyan
                        log -Status "INFORMATION" -Message " "
                        log -Status "INFORMATION" -Message "Display Name ---------------> ", $allADuser_DisplayName
                        log -Status "INFORMATION" -Message "Azure AD current UPN -------> ", $allAzureuser_UPN
                        log -Status "INFORMATION" -Message "Azure AD OnPremises UPN ----> ", $allGraphsuser_UPN

                        $isAcceptedDomain = $False
                        foreach ($AzureADDomain in $AzureADDomains)
                            {
                                $AzureADDomain_Name = $AzureADDomain.Name
                                if ($allGraphsuser_UPN -like "*$AzureADDomain_Name")
                                    {
                                        $isAcceptedDomain = $True
                                    }
                            }

                        if ($isAcceptedDomain -eq $False)
                            {
                                $NewUPN = $allADuser_UPN.split("@")[0] + "@" + $DomainToReplace
                                write-host "Action: Run the the following cmdlet on Active Directory Powershell:" -ForegroundColor Yellow
                                write-host  "set-aduser -identity", $allADuser_GUID, "-UserPrincipalName", $NewUPN
                                "#Changing to user UPN from " + $allADuser_UPN + " to " + $NewUPN | out-file -append $NeedToChangeOnPremiseUPN
                                "set-aduser -identity " + $allADuser_GUID + " -UserPrincipalName " + $NewUPN | out-file -append $NeedToChangeOnPremiseUPN
                            }
                            else
                                {
                                    write-host "Action: Run the the following cmdlet on Microsoft Onlibe (MSOL) Powershell:" -ForegroundColor Yellow
                                    write-host "Set-MsolUserPrincipalName -UserPrincipalName", $allAzureuser_UPN, "-NewUserPrincipalName", $allGraphsuser_UPN
                                    "Set-MsolUserPrincipalName -UserPrincipalName " + $allAzureuser_UPN + " -NewUserPrincipalName " + $allGraphsuser_UPN | out-file -append $NeedToRunPowerShell
                                }
                    }

            }
            catch
                {

                }
    }
Write-Host "Script finished successfully !!" -ForegroundColor Yellow
log -Status "INFORMATION" -Message "Script finished successfully !!"
log -Status "INFORMATION" -Message "..:: COMPLETED ::.."
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss;Write-Host $dateTime