# PowerShellScripts

PowerShell sample scripts to compare OnPremises users with Azure AD.

## Compare_UPN_from_AD_with_Azure.ps1

This script validates whether the UPN of all OnPremises AD users matches the UPN in Azure AD. Theoretically, this should always be the same, but I found several differences in the clients I've run it on.
Users with different UPNs are listed in two txt files generated by the script.

- The first log indicates users with invalid UPN domains in Office 365; these users need to have their UPN adjusted in OnPremises to a valid Office 365 domain.
- The second log indicates users with different UPN attributes but valid domains. In this case, you just need to execute the commands mentioned in the log.

IMPORTANT: The script only generates logs and does not make any changes in your environment.

## Collect_Orphan_Azure_Objects.ps1

This script validates whether Azure AD users have their corresponding objects in AD. Similarly, this should not exist, but...
Users who exist in Azure AD but no longer exist in AD are listed in two txt files generated by the script.

- The first log indicates users who no longer exist in AD but still exist in Azure AD and can be deleted.
- The second log serves as a double-check to validate that the user truly does not exist in AD.

IMPORTANT: The script only generates logs and does not make any changes in your environment.

## Compare_Country_from_AD_with_Azure.ps1

This script validates whether the Country attribute of all OnPremises AD users matches the Country in Azure AD. Theoretically, this should always be the same, but I found several differences in the clients I've run it on.
Users with different Country attribute are listed in the txt files generated by the script.

- The log indicates users with different Country attributes. In this case, you just need to execute the commands mentioned in the log.

IMPORTANT: The script only generates logs and does not make any changes in your environment.
