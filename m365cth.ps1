# Microsoft 365 data collector
# Designed to aid in cyber threat hunting
# Version: 1.0.0
# By: c1ph04

# Reference: https://learn.microsoft.com/en-us/office/office-365-management-api/aip-unified-audit-logs-best-practices

# Banner
Write-Host "

======================================================
Microsoft 365 Cyber Threat Hunting data collector
Version: 1.0.0
https://5shield.com/
By: c1ph04
======================================================

"

# Connect to M365 (ExchangeOnlineManagement Module 2.x or 3.x)
Write-Host "Connecting to Exchange Online...
"
Connect-ExchangeOnline -ShowBanner:$false

# Connect to Microsoft 365
Write-Host "Connecting to Microsoft 365...
"
Connect-MsolService

# Create an array to hold the login records
$userLoginRecords = @()

# Create hashtable to hold the IP information objects
$global:IPLookupInfo = @{}

# Set the search parameters
$startDate = (Get-Date).AddDays(-90)
$endDate = (Get-Date).AddDays(1)
$session = New-Guid
$resultSize = 5000

# Set the parameters for the search
$parameters = @{
    StartDate = $startDate
    EndDate = $endDate
    SessionId = $session
    SessionCommand = "ReturnLargeSet"
    RecordType = 'AzureActiveDirectoryStsLogon'
    Operations = @('UserLoggedIn', 'UserLoginFailed')
    ResultSize = $resultSize
    Formatted = $true
}

# Create Powershell Function for IP Information
function getIPInfo {
    
    Param($ipAddress)

    # If the IP info already exists return it
    if(!$IPLookupInfo[$ipAddress]) {

    # Else Get the IP Address information
    $response = Invoke-WebRequest "https://ipinfo.io/$ipAddress"

    # Extract what is needed
    $responseJson = $response.content | convertfrom-json | select ip,hostname,city,region,country,loc,org,postal,timezone

    # Put it in the hashtable
    
    $IPObject = [pscustomobject][ordered]@{

    'IP Address' = $responseJson.ip
    'Hostname' = $responseJson.hostname
    'City' = $responseJson.city
    'Region' = $responseJson.region
    'Country' = $responseJson.country
    'Location' = $responseJson.loc
    'Organization' = $responseJson.org
    'Zip' = $responseJson.postal
    'Timezone' = $responseJson.timezone
    
    }

    $IPLookupInfo.add($responseJson.ip, $IPObject)

   } else {
     
     $IPObject = $IPLookupInfo[$ipAddress]
   
   }
    
    # Return the object
    return $IPObject

}

##################################
# Login data (success, failures) #
##################################

Write-Host "Getting login data...
"

$userLoginData = Search-UnifiedAuditLog @parameters

# Get the result count
$resultCount = $userLoginData[0].ResultCount

# Get the number of results retrieved
$retrievedCount = $userLoginData.count

# If the ResultCount of the first record is greater than resultSize we need to subtract the number of records we received from the size to calculate how many we have left
if ($resultCount -gt $resultSize) {
    $remainingCount = $resultCount - $retrievedCount

    # If remaining count is greater than ResultSize
    $rounds = [MATH]::truncate($remainingCount / $resultSize)
    $lastRound = $remainingCount % $resultSize

    # Loop through main rounds
    foreach($i in 1..$rounds) {
        $userLoginData += Search-UnifiedAuditLog @parameters
    }

    # Change result size variable to lastRound
    $resultSize = $lastRound

    # Execute final one
    $userLoginData += Search-UnifiedAuditLog @parameters

}

# Sort and extract audit data
$userLogins = $userLoginData | Sort-Object -Property CreationDate -Descending | Select-Object AuditData -ExpandProperty AuditData | ConvertFrom-Json

# Collect useful information and get IP info
foreach ($userLogin in $userLogins) {

    if ($userLogin.ExtendedProperties.GetValue(1).Name -eq 'UserAgent') {
        
        $userAgent = $userLogin.ExtendedProperties.GetValue(1).Value
    
    } else {
        
        $userAgent = $userLogin.ExtendedProperties.GetValue(2).Value
        
    }


    if ($userLogin.DeviceProperties -ne $null -and $userLogin.DeviceProperties.GetValue(1).Name -eq 'DisplayName') {

        $computerName = $userLogin.DeviceProperties.GetValue(1).Value

        $operatingSystem = $userLogin.DeviceProperties.GetValue(2).Value
    
    } elseif ($userLogin.DeviceProperties -ne $null) {
        
        $computerName = "Not Available"

        $operatingSystem = $userLogin.DeviceProperties.GetValue(0).Value
    
    } else {

        $computerName = "Not Available"

        $operatingSystem = "Not Available"

    }


    if ($userLogin.ClientIP -eq '') {
        
        $IPAddress = "Not Available"
    
    } else {
    
        $IPAddress = $userLogin.ClientIP

        # Comment this out if you don't want to retrieve IP information, but then again...what would be the point?
        $IPInfo = getIPInfo($IPAddress)
    
    }


    $userLoginRecords += [pscustomobject][ordered]@{
    
    'Date' = $userLogin.CreationTime
    'User ID' = $userLogin.UserId
    'Operation' = $userLogin.Operation
    'IP Address' = $IPAddress
    'Region' = $IPInfo.Region
    'Country' = $IPInfo.Country
    'Organization' = $IPInfo.Organization
    'User-Agent' = $userAgent
    'Operating System' = $operatingSystem
    'Computer Name' = $computerName

    }

}

# Update retrieved count
$retrievedCount = $userLoginData.count

# Verify number of results is equal to the number of records retrieved
if ($resultCount -eq $retrievedCount) {
    Write-Host "Success: All $resultCount records have been successfully retrieved...
    "
} else {
    Write-Host "Warning: Only $retrievedCount of $resultCount could be retrieved...
    "
}

# Export the data to a CSV file
$userLoginRecords | Export-Csv UserLogins.csv -NoTypeInformation


###############################
# Mailbox rules / permissions #
###############################

Write-Host "Getting mailbox rules and permissions...
"

$Mailboxes = Get-Mailbox -ResultSize unlimited

foreach ($Mailbox in $Mailboxes) {
    Get-InboxRule -Mailbox $Mailbox.userprincipalname | fl MailboxOwnerId,Enabled,Name,Description >> MailBoxRules.txt
    Get-EXOMailBoxPermission $Mailbox.userprincipalname | where {$_.user -ne 'NT AUTHORITY\SELF'} >> MailBoxPermissions.txt
} 

####################
# Forwarding rules #
####################

Write-Host "Getting mailbox forwarding rules...
"

Get-Mailbox -Filter {DeliverToMailboxAndForward -ne $False} | select UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward | export-csv -notypeinformation ForwardingRules.csv


####################
# Get MFA Status   #
####################

Write-Host "Getting MFA status...
"

Get-MsolUser -All | where {$_.UserPrincipalName -notlike '*#EXT#*'} | sort UserPrincipalName |  select DisplayName,BlockCredential,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationRequirements.State -ne $null){ $_.StrongAuthenticationRequirements.State} else { "Disabled"}}} | export-csv -NoTypeInformation MFAStatus.csv


####################
# Finish           #
####################

Write-Host "Data collection finished...happy hunting!
"