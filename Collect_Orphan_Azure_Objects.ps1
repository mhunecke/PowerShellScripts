<#
.Synopsis
    Script to collect all the orphan users in Azure AD. Users created by sync from AD, but the users does not exist in AD anymore.
.DESCRIPTION
    Script to collect all the orphan users in Azure AD. Users created by sync from AD, but the users does not exist in AD anymore.
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
    FileName:       .\Collect_Orphan_Azure_Objects.ps1
    Author:         Marcelo Hunecke - Microsoft (mhunecke@microsoft.com)
    Creation date:  Aug 10th, 2023
    Last update:    Sep 06th, 2023
    Version:        1.51
    Changelog:
    ==========
    1.50 - Aug 24th, 2023
        - Ignore "Sync_<GUID>" users. This users are created by Azure AD Connect and are not synced from OnPremises Active Directory.
    1.51 - Sep 06th, 2023
        - Rename the script to Collect_Orphan_Azure_Objects.ps1
        - Change some variable names, just for standardization
#>

$DateTime = Get-Date -Format yyyy_M_d@HH_mm_ss
$RunOnPremises = "Collect_Orphan_Azure_Objects_RunOnPremises_" + $DateTime + ".txt"
$RunOnCloud = "Collect_Orphan_Azure_Objects_RunOnCloud_" + $DateTime + ".txt"
$logName = "Collect_Orphan_Azure_Objects_ExecutionLog_" +  $DateTime + ".txt"

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
# Script start here
#---------------------------------------------------------------------

Clear-Host
#[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
#[Net.ServicePointManager]::SecurityProtocol
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss;Write-Host $dateTime
log -Status "INFORMATION" -Message "..:: STARTED ::.."

ConnectAzureAD

$TotalUsersCounter = 0
$UsersToChangeCounter = 0
"# Run these cmdlets on OnPremises Active Directory PowerShell" | out-file $RunOnPremises
"#---------------------------------------------------------------------------" | out-file -append $RunOnPremises
"# Run these cmdlets on Azure AD PowerShell | Connect-AzureAD" | out-file $RunOnCloud
"#---------------------------------------------------------------------------" | out-file -append $RunOnCloud
Write-Host "Reading Azure AD Users... (wait around 10 minutes for each 10k Azure AD users) !!"
log -Status "INFORMATION" -Message "Reading Azure AD Users... (wait around 10 minutes for each 10k Azure AD users) !!"
$allAzureADusers = Get-AzureADUser -all:$true | Where-Object {$_.DirSyncEnabled -eq $true -and $_.UserType -eq "Member" -and $_.UserPrincipalName -notlike "Sync_*"} | select-object UserPrincipalName, ObjectID, OnPremisesSecurityIdentifier, DisplayName, OnPremisesDistinguishedName
$allAzureADusersCount = $allAzureADusers.count

foreach ($allAzureADuser in $allAzureADusers)
    { 
        $TotalUsersCounter++
        $PercentComplete = ($TotalUsersCounter / $allAzureADusersCount) * 100
        Write-Progress -Activity 'Reading user attributes...' -Status "$TotalUsersCounter users of $allAzureADusersCount users already checked." -PercentComplete $PercentComplete

        $allAzureADuser_UPN = $allAzureADuser.UserPrincipalName
        $allAzureADuser_ObjectID = $allAzureADuser.ObjectID
        $allAzureADuser_OnPremSID = $allAzureADuser.OnPremisesSecurityIdentifier
        $allAzureADuser_DisplayName = $allAzureADuser.DisplayName
        try
            {
                $allADOnPremUser = Get-ADUser -identity $allAzureADuser_OnPremSID -Properties ObjectGUID | select-object UserPrincipalName, ObjectGUID # -ErrorAction Stop
            }
            catch
                {
                    $UsersToChangeCounter++
                    Write-Host
                    Write-Host "#", $UsersToChangeCounter
                    Write-Host "Azure AD Display Name --------> ", $allAzureADuser_DisplayName -ForegroundColor Cyan
                    Write-Host "Azure AD current UPN ---------> ", $allAzureADuser_UPN -ForegroundColor Cyan
                    "Get-ADUser -Identity '" + $allAzureADuser_DisplayName + "'" | out-file -append $RunOnPremises
                    "Get-ADUser -Identity '" + $allAzureADuser_UPN + "'" | out-file -append $RunOnPremises
                    "Get-ADUser -Identity '" + $allAzureADuser_OnPremSID + "'" | out-file -append $RunOnPremises
                    "#---------------------------------------------------------------------------" | out-file -append $RunOnPremises
                    Write-Host "Action: Run the the following cmdlet on Azure AD PowerShell:" -ForegroundColor Yellow
                    Write-Host "Remove-AzureADuser -ObjectID", $allAzureADuser_ObjectID
                    "Remove-AzureADuser -ObjectID " + $allAzureADuser_ObjectID | out-file -append $RunOnCloud

                    log -Status "INFORMATION" -Message ""
                    log -Status "INFORMATION" -Message "#", $UsersToChangeCounter
                    log -Status "INFORMATION" -Message "Azure AD Display Name --------> ", $allAzureADuser_DisplayName
                    log -Status "INFORMATION" -Message "Azure AD current UPN ---------> ", $allAzureADuser_UPN
                    log -Status "INFORMATION" -Message "Action: Run the the following cmdlet on Azure AD PowerShell:"
                    log -Status "INFORMATION" -Message "Remove-AzureADuser -ObjectID", $allAzureADuser_ObjectID
                }
    }

Write-Host 
Write-Host "Script finished successfully !!" -ForegroundColor Yellow
log -Status "INFORMATION" -Message ""
log -Status "INFORMATION" -Message "Script finished successfully !!"
log -Status "INFORMATION" -Message "..:: COMPLETED ::.."
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss
Write-Host $dateTime