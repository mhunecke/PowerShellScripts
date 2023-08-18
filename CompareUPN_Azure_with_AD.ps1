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
    Creation date:  Aug 1oth, 2023
    last update:    Aug 16th, 2023
    Version:        1.3

#>

$GADC = "ADWDC04P01.gerdau.net"
$DateTime = Get-Date -Format yyyy_M_d@HH_mm_ss
$NeedToChangeOnPremiseUPN = "CompareUPN_Azure_NeedToChangeOnPremiseUPN_" + $DateTime + ".txt"
$NeedToRunPowerShell = "CompareUPN_Azure_NeedToRunPowerShell_" + $DateTime + ".txt"
$logName = "CompareUPN_Azure_Log_" +  $DateTime + ".txt"
$DomainToReplace = "gerdau.com"

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
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#[Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
#[Net.ServicePointManager]::SecurityProtocol
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss;Write-Host $dateTime
log -Status "INFORMATION" -Message "..:: STARTED ::.."

ConnectAzureAD
#ConnectMSGraph
#ConnectMsol

$UserCounter = 0
$CountDelete = 0
"#Run these cmlets on Active Directory PowerShell" | out-file $NeedToChangeOnPremiseUPN
"#---------------------------------------------------------------------------" | out-file -append $NeedToChangeOnPremiseUPN
"#Run these cmlets on Microsoft Online PowerShell | Connect-AzureAD" | out-file $NeedToRunPowerShell
write-host "Reading Azure AD Users...."
log -Status "INFORMATION" -Message "Reading Active Directory Users...."
#$allAzureADusers = Get-AzureADUser -All $true | select-object UserPrincipalName, ObjectID

#$allAzureADusers = Get-AzureADUser -searchstring "Microsoft" | Where-Object {($_.DirSyncEnabled -eq $true) -and ($_.UserType -eq "Member")}  | select-object UserPrincipalName, ObjectID, OnPremisesSecurityIdentifier, DisplayName, OnPremisesDistinguishedName
$allAzureADusers = Get-AzureADUser -all:$true | Where-Object {($_.DirSyncEnabled -eq $true) -and ($_.UserType -eq "Member")}  | select-object UserPrincipalName, ObjectID, OnPremisesSecurityIdentifier, DisplayName, OnPremisesDistinguishedName

$allAzureADusersCount = $allAzureADusers.count

foreach ($allAzureADuser in $allAzureADusers)
    {
        
        $UserCounter++
        $PercentComplete = ($UserCounter / $allAzureADusersCount) * 100
        Write-Progress -Activity 'Reading user attributes...' -Status "$UserCounter users of $allAzureADusersCount users already checked." -PercentComplete $PercentComplete
        
        $allAzureADuser_UPN = $allAzureADuser.UserPrincipalName
        $allAzureADuser_ObjectID = $allAzureADuser.ObjectID
        $allAzureADuser_OnPremSID = $allAzureADuser.OnPremisesSecurityIdentifier
        #$allAzureADuser_ImmutableID = $allAzureADuser.ImmutableID
        #$allAzureADuser_ObjectGUID = [Guid]([System.Convert]::FromBase64String($allAzureADuser_ImmutableID))
        $allAzureADuser_DisplayName = $allAzureADuser.DisplayName
        #Write-Host $allAzureADuser_UPN
        #Write-Host $allAzureADuser_ObjectID
        #Write-Host $allAzureADuser_ImmutableID
        #Write-Host $allAzureADuser_ObjectGUID
        #Write-Host $allAzureADuser_DisplayName
        

        #Get-AzureADUSerExtension -ObjectID $allAzureADuser_ObjectID | select-object OnPremisesDistinguishedName | Out-Null
        #$allAzureAdUserExtension_OnPremDN = $allAzureAdUserExtension.OnPremisesDistinguishedName

        #$allGraphsuser = Get-MgUser -UserId $allAzureADuser_ObjectID -Property OnPremisesUserPrincipalName, OnPremisesDistinguishedName | select-object OnPremisesUserPrincipalName, OnPremisesDistinguishedName #-ErrorAction Stop
        #$allGraphsuser_DN = $allGraphsuser.OnPremisesDistinguishedName
        #$allGraphsuser_UPN = $allGraphsuser.OnPremisesUserPrincipalName
        #Write-host $allGraphsuser_DN -ForegroundColor Yellow
        #Write-host $allGraphsuser_UPN -ForegroundColor Yellow

        try
            {
                $allADOnPremUser = Get-ADUser -identity $allAzureADuser_OnPremSID -Properties ObjectGUID | select-object UserPrincipalName, ObjectGUID # -ErrorAction Stop
                $allADOnPremUser_UPN = $allADOnPremUser.userprincipalname
                $allADOnPremUser_ObjectGUID = $allADOnPremUser.ObjectGUID
                #Write-host $allADOnPremUser_UPN -ForegroundColor Green
                #Write-host $allADOnPremUser_ObjectGUID -ForegroundColor Green
            }
            catch
                {
                    $CountDelete++
                    write-host
                    write-host "#",$CountDelete
                    write-host "Azure AD Display Name --------> ", $allAzureADuser_DisplayName -ForegroundColor Cyan
                    Write-host "Azure AD current UPN ---------> ", $allAzureADuser_UPN -ForegroundColor Cyan
                    #Write-host "Microsoft Graph DN -----------> ", $allAzureAdUserExtension_OnPremDN -ForegroundColor Cyan
                    Write-Host "Active Directory ObjectGUID --> ", $allAzureADuser_ObjectGUID -ForegroundColor Cyan
                    "Get-ADUser -Identity '" + $allAzureADuser_DisplayName + "'" | out-file -append $NeedToChangeOnPremiseUPN
                    "Get-ADUser -Identity '" + $allAzureADuser_UPN + "'" | out-file -append $NeedToChangeOnPremiseUPN
                    #"Get-ADUser -Identity '" + $allAzureAdUserExtension_OnPremDN + "'" | out-file -append $NeedToChangeOnPremiseUPN
                    "Get-ADUser -Identity '" + $allAzureADuser_OnPremSID + "'" | out-file -append $NeedToChangeOnPremiseUPN
                    "#---------------------------------------------------------------------------" | out-file -append $NeedToChangeOnPremiseUPN
                    write-host "Action: Run the the following cmdlet on Azure AD PowerShell:" -ForegroundColor Yellow
                    write-host "Remove-AzureADuser -ObjectID", $allAzureADuser_ObjectID
                    "Remove-AzureADuser -ObjectID " + $allAzureADuser_ObjectID | out-file -append $NeedToRunPowerShell
                }

               
    }
write-host 
Write-Host "Script finished successfully !!" -ForegroundColor Yellow
log -Status "INFORMATION" -Message "Script finished successfully !!"
log -Status "INFORMATION" -Message "..:: COMPLETED ::.."
$dateTime = Get-Date -Format dd/MM/yyyy-HH:mm:ss;Write-Host $dateTime