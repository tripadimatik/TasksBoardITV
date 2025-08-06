# PowerShell script to generate SSL certificates using .NET crypto

Write-Host "Generating SSL certificates..." -ForegroundColor Green

# Create certs directory if it doesn't exist
if (!(Test-Path 'server\certs')) {
    New-Item -ItemType Directory -Path 'server\certs' -Force | Out-Null
}

# Define paths
$certPath = 'server\certs\cert.pem'
$keyPath = 'server\certs\key.pem'

# Generate RSA key pair
Add-Type -AssemblyName System.Security
$rsa = [System.Security.Cryptography.RSA]::Create(2048)

# Create certificate request
$req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=localhost',
    $rsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

# Add extensions
$sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$sanBuilder.AddDnsName('localhost')
$sanBuilder.AddIpAddress([System.Net.IPAddress]::Parse('192.168.8.69'))
$req.CertificateExtensions.Add($sanBuilder.Build())

# Key usage
$keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
    $true
)
$req.CertificateExtensions.Add($keyUsage)

# Extended key usage
$eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
    [System.Security.Cryptography.Oid[]]@([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')), # Server Authentication
    $true
)
$req.CertificateExtensions.Add($eku)

# Create self-signed certificate
$cert = $req.CreateSelfSigned([System.DateTimeOffset]::Now, [System.DateTimeOffset]::Now.AddYears(1))

# Export certificate
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$certPem = '-----BEGIN CERTIFICATE-----' + [Environment]::NewLine
$certPem += [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
$certPem += [Environment]::NewLine + '-----END CERTIFICATE-----'
$certPem | Out-File -FilePath $certPath -Encoding ASCII

# Export private key
$keyBytes = $rsa.ExportPkcs8PrivateKey()
$keyPem = '-----BEGIN PRIVATE KEY-----' + [Environment]::NewLine
$keyPem += [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
$keyPem += [Environment]::NewLine + '-----END PRIVATE KEY-----'
$keyPem | Out-File -FilePath $keyPath -Encoding ASCII

# Clean up
$cert.Dispose()
$rsa.Dispose()

Write-Host "SSL certificates generated successfully!" -ForegroundColor Green
Write-Host "Certificate: $certPath" -ForegroundColor Yellow
Write-Host "Private Key: $keyPath" -ForegroundColor Yellow
Write-Host "" 
Write-Host "Certificates are ready for HTTPS configuration." -ForegroundColor Cyan