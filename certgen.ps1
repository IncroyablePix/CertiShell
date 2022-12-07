### Programs ###
Function CreateCertificate() 
{
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string] $DomainName
	)	
	$InstallCertificate = Read-Host "Do you want to install the certificate? (y/n)"
	$Password = Read-Host "Enter the password for the certificate (Leave empty for no password)" -AsSecureString
	
	$IntermediateCertificate = Read-Host "Enter the path to the Root or Intermediate certificate (.pfx) or leave empty for no intermediate certificate"
	$IntermediateCertificatePassword = $null
	$RootCertificate = $null
	$FileExists = Test-Path -Path $IntermediateCertificate

	if($IntermediateCertificate -and $FileExists)
	{
		$IntermediateCertificatePassword = Read-Host "Enter the password for the Root or Intermediate certificate" -AsSecureString
		$RootCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$RootCertificate.Import($IntermediateCertificate, $IntermediateCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
	}
	
	$Certificate = CreateCertfile -Name $DomainName -Password $Password -Type Certificate -Install ($InstallCertificate -eq "y") -ChainCertificate $RootCertificate
	
	Write-Host "Certificate created" -ForegroundColor Green
	
	Exit
}

Function DeleteCertificate()
{
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string] $DomainName
	)
	
	$CertificateEntry = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object {$_.Subject -Match "$DomainName"} | Select-Object Thumbprint, FriendlyName
	
	$Thumbprints = $CertificateEntry.Thumbprint.Split(" ");
	
	foreach($Thumbprint in $Thumbprints)
	{
		Remove-Item -Path "Cert:\CurrentUser\My\$Thumbprint" -DeleteKey
		Write-Host "Removed $($DomainName) certificate at $($Thumbprint)" -ForegroundColor Green
	}
	
	Exit
}

Function CreateCA()
{
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string] $Name,
		[Parameter(Mandatory = $true, Position = 1)]
		[string] $FriendlyName
	)

	$Password = Read-Host "Enter the password for the CA (Leave empty for no password)" -AsSecureString
	$CreateIntermediate = Read-Host "Do you want to create an intermediate certificate as well? (y/n)"
	
	$Certificate = CreateCertfile -Name $Name -FriendlyName $FriendlyName -Password $Password -Type CA -Install $false
	
	if($CreateIntermediate -eq "y")
	{
		$Intermediate = CreateCertfile -Name $Name -Password $Password -Type Intermediate -Install $false -ChainCertificate $Certificate
		
		$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("CA", "LocalMachine")
		$Store.Open("ReadWrite")
		$Store.Add($Intermediate)
		$Store.Close()
	}
	
	$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
	$Store.Open("ReadWrite")
	$Store.Add($Certificate)
	$Store.Close()

	$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store "CA", "LocalMachine"
	$Store.Open("ReadWrite")
	$Store.Remove($Certificate)
	$Store.Close()

	Write-Host "Created and installed CA Certificates for current user" -ForegroundColor Green	

	Exit
}

Function InstallCertificateCA()
{
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string] $CertificatePath
	)

	if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "Please run this command as an administrator" -ForegroundColor Red
		Exit
	}
	
	$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	$Certificate.Import($CertificatePath)
	$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
	$Store.Open("ReadWrite")
	$Store.Add($Certificate)
	$Store.Close()
	
	Write-Host "Installed certificate to Trusted Root Certificate Authorities" -ForegroundColor Green
}

Function UninstallCertificateCA() 
{
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string] $CertificatePath
	)
	
	if(-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Host "Please run this command as an administrator" -ForegroundColor Red
		Exit
	}
	
	$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	$Certificate.Import($CertificatePath)
	$Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
	$Store.Open("ReadWrite")
	$Store.Remove($Certificate)
	$Store.Close()
	
	Write-Host "Uninstalled certificate from Trusted Root Certificate Authorities" -ForegroundColor Green
}

Function InstallCertificate() 
{
	Param
	(
		[Parameter(Mandatory = $true, Position = 0)]
		[string] $CertificatePath
	)
	
	$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	$Certificate.Import($CertificatePath)
	
	$Store = New-Object System.Security.Cryptography.X509Certificates
	$Store.Open("ReadWrite")
	$Store.Add($Certificate)
	$Store.Close()

	Write-Host "Installed certificate for current user" -ForegroundColor Green
}

### Common ###
Function CreateCertfile()
{
	Param
	(
		[Parameter(Mandatory = $false, Position = 0)]
		[SecureString] $Password,
		[Parameter(Mandatory = $true, Position = 1)]
		[string] $Name,
		[Parameter(Mandatory = $false, Position = 2)]
		[string] $FriendlyName,
		[Parameter(Mandatory = $false, Position = 3)]
        $ChainCertificate,
		[Parameter(Mandatory = $true, Position = 4)]
		[string] $Type,
		[Parameter(Mandatory = $true, Position = 5)]
		[bool] $Install
	)

	$CertificatePath = ""
	$PrivateKeyPath = ""
	$CertStoreLocation = ""
    $CertUsages = @()
    # @("CertSign","CRLSign", "DataEncipherment", "DecipherOnly", "DigitalSignature", "EncipherOnly","KeyAgreement", "KeyEncipherment", "NonRepudiation");

	if($Type -eq "CA")
	{
		$Name = "$($Name) Root CA"
		$CertificatePath = "$($pwd.Path)\$($Name).cer"
		$PrivateKeyPath = "$($pwd.Path)\$($Name).pfx"
		$CertStoreLocation = "Cert:\LocalMachine\My" # Then move to... "Cert:\LocalMachine\Root"
        $CertUsages = @("CertSign")
	}
	elseif($Type -eq "Intermediate")
	{
		$Name = "$($Name) Intermediate CA"
		$CertificatePath = "$($pwd.Path)\$($Name).cer"
		$PrivateKeyPath = "$($pwd.Path)\$($Name).pfx"
		$CertStoreLocation = "Cert:\LocalMachine\Intermediate"
        $CertUsages = @("CertSign")
	}
	else
	{
		$CertificatePath = "$($pwd.Path)\$($Name).cer"
		$PrivateKeyPath = "$($pwd.Path)\$($Name).pfx"
		$CertStoreLocation = "Cert:\CurrentUser\My"
	}

	$CmdParams = 
	@{
		DnsName = $Name;
		KeyExportPolicy = "Exportable";
		KeySpec = "Signature";
		KeyLength = 2048;
		HashAlgorithm = "SHA256";
		KeyAlgorithm = "RSA";
        KeyUsage = $CertUsages;
	}

	if($ChainCertificate -ne $null)
	{
		$CmdParams.Add("Signer", $ChainCertificate)
	}

	if($Install -eq $true)
	{
		$CmdParams.Add("CertStoreLocation", $CertStoreLocation)
	}

	if($FriendlyName -ne $null)
	{
		$CmdParams.Add("FriendlyName", $FriendlyName)
	}
	
	$Certificate = New-SelfSignedCertificate @CmdParams
	
	$Export = Export-Certificate -Cert $Certificate -FilePath $CertificatePath
	$ExportPfx = Export-PfxCertificate -Cert $Certificate -FilePath $PrivateKeyPath -Password $Password
	
	return $Certificate
}

Function Display-Commands 
{
	$Commands = 
	@{
		Create = "Create a new certificate";
		CreateCA = "Create a new certificate authority";
		Delete = "Delete a certificate";
		InstallCA = "Install a trusted root certification authority";
		RemoveCA = "Remove a trusted root certification authority";
		Install = "Install a certificate in trust store for current user";
	}
	
	foreach($Key in $Commands.Keys) 
	{
		if($Key.Length -gt 7)
		{
			Write-Host "`t$($Key)`t" -NoNewLine -ForegroundColor DarkBlue -BackgroundColor Yellow
		}
		else
		{
			Write-Host "`t$($Key)`t`t" -NoNewLine -ForegroundColor DarkBlue -BackgroundColor Yellow
		}
		Write-Host "$($Commands[$Key])"
	}
}

Function Display-SyntaxError()
{
	Param
	(
		[Parameter(Position=0)]
		[string] $Error
	)
	
	Write-Host "Error" -NoNewLine -ForegroundColor DarkRed
	Write-Host ": " -NoNewLine
	Write-Host "$($Error)"
	
	Write-Host "Commands:"
	Display-Commands
	
	Exit 
}

### Entrypoint ###
if (Get-Module -ListAvailable -Name Microsoft.PowerShell.Security) 
{
    Write-Host "PKI Module exists"
} 
else 
{
    Write-Host "Module PKI could not be found" -ForegroundColor Red
}

if($args.Count -lt 1)
{
	Display-SyntaxError -Error "Usage $($MyInvocation.MyCommand.Name) <command>"
}

$CommandFunctions = 
@{
	"Create" = $Function:CreateCertificate;
	"CreateCA" = $Function:CreateCA;
	"Delete" = $Function:DeleteCertificate;
	"InstallCA" = $Function:InstallCertificateCA;
	"RemoveCA" = $Function:UninstallCertificateCA;
	"Install" = $Function:InstallCertificate;
}

$CommandName = $args[0]

if(!$CommandFunctions.Contains($CommandName))
{
	Display-SyntaxError -Error "Invalid command`nUsage $($MyInvocation.MyCommand.Name) <command>"
}

$Command = $CommandFunctions["$($CommandName)"]
&cls
&$Command
