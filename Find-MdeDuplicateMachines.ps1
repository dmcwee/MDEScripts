[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$ResourceAppId = "https://api.securitycenter.microsoft.com",
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [Parameter(Mandatory=$true)]
    [string]$ApplicationId,
    [Parameter(Mandatory=$true)]
    [string]$AppSecret,
    [switch]$AutoTag
)

function Get-Token {
    [CmdletBinding()]
    param(
        $resourceAppIdUri = '',
        $oAuthUri = 'https://login.microsoftonline.com/{0}/oauth2/token',
        $tenantId,
        $appId,
        $appSecret
    )

    $oAuthUri = $oAuthUri -f $tenantId
    Write-Debug ("oAuthUri:" + $oauthUri)

    $authBody = [Ordered] @{
        resource = $resourceAppIdUri
        client_id = $appId
        client_secret = $appSecret
        grant_type = 'client_credentials'
    }
    
    $jsonBody = ConvertTo-Json $authBody
    Write-Debug ("BODY:" + $jsonBody)

    $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    Write-Debug ("respose:" + $response)

    $response.access_token
}

function Invoke-ApiCall {
    [CmdletBinding()]
    param(
        $Uri = "",
        $Method = "Get",
        $Bearer = "",
        $Body = ""
    )

    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $Bearer" 
    }

    $headerJson = ConvertTo-Json $headers
    Write-Debug ("Headers: " + $headerJson)

    Write-Debug "Uri: $Uri"
    Write-Debug "Method: $Method"
    Write-Debug "Body: $Body"

    $webResponse = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $headers -ErrorAction Stop
    
    Write-Debug "webResponse: $webResponse"
    $webResponse | ConvertFrom-Json
}

$api = "https://api.securitycenter.microsoft.com/api/machines"
$token = Get-Token -resourceAppIdUri $ResourceAppId -tenantId $TenantId -appId $ApplicationId -appSecret $AppSecret
$result = Invoke-ApiCall -Uri $api -Bearer $token

$potentialDups = $result.value | Where {$_.isPotentialDuplication -ne $false}

#if($AutoTag) {
#    $action = "Post"
#    $api = "https://api.securitycenter.microsoft.com/api/machines/{0}/tags"
#    $body = "{\"Value\":\"PotentialDuplicate\",\"Action\":\"Add\"}"

#    $potentialDups | ForEach-Object {
#        $callApi = $api -f $_.id
#        Invoke-WebRequest -Uri $api -Bearer $ -Method $action -Body $body
#    }
#}
#else {
    $result.value | Select-Object -Property id,computerDnsName,osPlatform,osVersion,osProcessor,version,lastIpAddress,isExcluded,isPotentialDuplication,mergedIntoMachineId | Export-Csv dup.txt -NoTypeInformation
#}