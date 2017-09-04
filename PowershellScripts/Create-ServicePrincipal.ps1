<#
.Powershell Version : 5.0

.Pre-requisites to run this script -

    Required Modules & Version-
    AzureRM  4.1.0
    AzureADPreview  2.0.0.129

    You can Install the required modules by executing below command.
    Install-Module AzureRM
    Install-Module AzureADPreview

    Account permissions -
    The account to execute this script must be an Azure AD Account with Global Administrator Permission at Tenant level and Owner permission at Subscription level.

.Description

	This script creates an AD Application, Service Principal, Add Response URL and Grant permission at Subscription or ResourceGroup level. By default this will grant 'Reader'
	permission to the App if only SubscriptionID is provided as a parameter input. This script requires SubscriptionID as a mandatory input. 

.Example 
	 Creates a service principal without response url.
    .\Create-ServicePrincipal.ps1 -subscriptionId xxxxxxx-xxxx-xxxx-xxxx-xxxxxxx

.Example 
	Creates a Service Principal with response url.
	.\Create-ServicePrincipal.ps1 -subscriptionId xxxxxxx-xxxx-xxxx-xxxx-xxxxxxx -dnsNameLabel tjgj7s-enterprise.eastus.cloudapp.azure.com
	
.Example 
	Creates an App and grant Contributor permission at Subscription.	
	.\Create-ServicePrincipal.ps1 -subId 'xxxxxxx-xxxx-xxxx-xxxx-xxxxxxx' -prefix 'AdApp' -def 'Contributor' -scope Subscription

.Example 
	Creates an App and grant Contributor permission at given Resource Group.	
	.\Create-ServicePrincipal.ps1 -subId 'xxxxxxx-xxxx-xxxx-xxxx-xxxxxxx' -prefix 'AdApp' -def 'Contributor' -scope ResourceGroup -resourceGroupName 'testResourceGroup'

#>

Param (

 # Provide Subscription ID
 [Parameter(Mandatory=$true, 
 Position=0,
 ParameterSetName='Parameter Set 1')]
 [ValidateNotNull()]
 [Alias("subId")] 
 $subscriptionId,

 # Provide public DNS name label for cloudneeti application. if you are accessing it using azure dns label then enter the same. e.g. cnbasic.eastus2.cloudapp.azure.com
 [Parameter(Mandatory=$false, 
 Position=1,
 ParameterSetName='Parameter Set 1')]
 [ValidateNotNull()]
 [Alias("dnsName")] 
 $dnsNameLabel = 'null',

  # Provide displayname suffix for AD application.
  [Parameter(Mandatory=$false, 
  Position=2,
  ParameterSetName='Parameter Set 1')]
  [ValidateNotNull()]
  [Alias("prefix")] 
  $adApplicationDisplayNamePrefix = 'cloudneeti',

  # Name of the RBAC role that needs to be assigned to the principal i.e. Reader, Contributor, Virtual Network Administrator, etc.
  [Parameter(Mandatory=$false, 
  Position=3,
  ParameterSetName='Parameter Set 1')]
  [ValidateNotNull()]
  [Alias("def")] 
  $roleDefinitionName = 'Reader',

  # The Scope of the role assignment
  [Parameter(Mandatory=$false, 
  Position=4,
  ParameterSetName='Parameter Set 1')]
  [ValidateSet ("Subscription", "ResourceGroup")]
  $scope = 'Subscription',

  # The Resource Group Name to assing permission.
  [Parameter(Mandatory=$false, 
  Position=5,
  ParameterSetName='Parameter Set 1')]
  [ValidateNotNull()]
  [ValidateScript({$scope -eq 'ResourceGroup'})]   
  $resourceGroupName

)

# Function to create a strong 15 length Strong & Random password
function New-AesManagedObject($key, $IV) {

    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256

    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }

    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }

    $aesManaged
}

function New-AesKey() {
    $aesManaged = New-AesManagedObject 
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

$ErrorActionPreference = 'Stop'

Import-Module AzureRM.Resources
Import-Module AzureADPreview

try {

	# To login to Azure Resource Manager
	Write-Host ("1: Logging in to Azure Subscription " + $SubscriptionId) -ForegroundColor Yellow
	Try  
	{  
		Get-AzureRmSubscription -SubscriptionId $subscriptionId
		$context = Set-AzureRmContext -SubscriptionId $subscriptionId
	}  
	Catch
	{  
		Login-AzureRmAccount -SubscriptionId $SubscriptionId
		$context = Set-AzureRmContext -SubscriptionId $SubscriptionId
	} 

	switch ($scope) {
		'Subscription' { $scopeUri = "/subscriptions/" + $SubscriptionId }
		'ResourceGroup' { $scopeUri = "/subscriptions/" + $SubscriptionId + '/resourceGroups/' + $resourceGroupName }
	}

	$homePageURL = ("http://www.cloudneeti.com")
	$applicationDisplayName = ($adApplicationDisplayNamePrefix + (Get-Random -Minimum 100 -Maximum 999))
	$identifierUris = "http://" + $applicationDisplayName

	# Create Active Directory Application
	try
	{
		Write-Host -ForegroundColor Yellow "2: Creating a new azure active directory application - $applicationDisplayName."
		#Create the 44-character key value
		$keyValue = New-AesKey

		# create the PSADPasswordCredential and populated it with start and end dates, a generated GUID, and my key value:
		$psadCredential = New-Object Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADPasswordCredential
		$startDate = Get-Date
		$psadCredential.StartDate = $startDate
		$psadCredential.EndDate = $startDate.AddYears(100)
		$psadCredential.KeyId = [guid]::NewGuid()
		$psadCredential.Password = $KeyValue

		$azureAdApplication = New-AzureRmADApplication -DisplayName $applicationDisplayName -HomePage $homePageURL -IdentifierUris $identifierUris -PasswordCredentials $psadCredential

	}
	catch [System.Exception]
	{
		throw $_
	}

	# Update Azure AD Application with Response URLs.
	if($dnsNameLabel -ne 'null'){
		$ReplyUrls = "http://" + $dnsNameLabel + '/Account/SignIn'
		Set-AzureRmADApplication -ObjectId $azureAdApplication.ObjectId -ReplyUrls $ReplyUrls
	}

	# Create Service Principal for the AD app
	Write-Host -ForegroundColor Yellow "3: Creating a new azure active directory service principal for applicationClientID - $($azureAdApplication.ApplicationId)"
	$servicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $azureAdApplication.ApplicationId
	$newRole = $null
	$retries = 0;

	While ($newRole -eq $null -and $retries -le 6)
	 {
		# Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
		Start-Sleep 30
		New-AzureRMRoleAssignment -RoleDefinitionName $roleDefinitionName -ServicePrincipalName $servicePrincipal.ApplicationId -Scope $scopeUri | Write-Verbose -ErrorAction SilentlyContinue
		$newRole = Get-AzureRMRoleAssignment -ServicePrincipalName $servicePrincipal.ApplicationId -ErrorAction SilentlyContinue
		$retries++;
	 }

	# Create Access Token Policy for Service Principal with one day expiry.
	Write-Host -ForegroundColor Yellow "4: Creating access token policy for service principal with one day expiry."
	Connect-AzureAD
	$adPolicy = New-AzureADPolicy -Definition @('{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"23:59:59","MaxAgeSessionSingleFactor":"23:59:59"}}') -DisplayName "CloudneetiAppToken" -IsOrganizationDefault $false -Type "TokenLifetimePolicy"
	Add-AzureADServicePrincipalPolicy -Id $servicePrincipal.Id.Guid -RefObjectId $adPolicy.id

	############### SCRIPT OUTPUT ##########################

	Write-Host -ForegroundColor Yellow "`n5: Copy and provide the below information while configuring Cloudneeti."

	$Output = @{
		"DomainName" = ($context.Account.Id -split '@')[1];
		"TenantId" = $context.Tenant.Id;
		"SubscriptionId" = $context.Subscription.Id;
		"ADApplicationName" = $azureAdApplication.DisplayName;
		"ADApplicationClientId" = $azureAdApplication.ApplicationId;
		"ADApplicationPassword" = $KeyValue;
	}

	Write-Host -ForegroundColor Yellow "$($Output | Out-String)"

}
catch {
    Throw $_
}