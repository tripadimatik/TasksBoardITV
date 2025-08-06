@echo off
setlocal enabledelayedexpansion

echo Generating SSL certificates with PowerShell...

powershell -ExecutionPolicy Bypass -Command "
$certParams = @{
    Subject = 'CN=localhost'
    DnsName = @('localhost', '192.168.8.69')
    KeyUsage = 'DigitalSignature', 'KeyEncipherment'
    KeyUsageProperty = 'All'
    KeyExportPolicy = 'Exportable'
    NotAfter = (Get-Date).AddYears(1)
    CertStoreLocation = 'Cert:\CurrentUser\My'
    KeyAlgorithm = 'RSA'
    KeyLength = 2048
    Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
    HashAlgorithm = 'SHA256'
}

$cert = New-SelfSignedCertificate @certParams

# Export certificate
$certPath = 'server\certs\cert.pem'
$keyPath = 'server\certs\key.pem'

# Create certs directory if it doesn't exist
if (!(Test-Path 'server\certs')) {
    New-Item -ItemType Directory -Path 'server\certs' -Force
}

# Export certificate in PEM format
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$certPem = '-----BEGIN CERTIFICATE-----' + [Environment]::NewLine
$certPem += [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
$certPem += [Environment]::NewLine + '-----END CERTIFICATE-----'
$certPem | Out-File -FilePath $certPath -Encoding ASCII

# Export private key
$keyBytes = $cert.PrivateKey.ExportPkcs8PrivateKey()
$keyPem = '-----BEGIN PRIVATE KEY-----' + [Environment]::NewLine
$keyPem += [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
$keyPem += [Environment]::NewLine + '-----END PRIVATE KEY-----'
$keyPem | Out-File -FilePath $keyPath -Encoding ASCII

# Remove certificate from store
Remove-Item -Path \"Cert:\CurrentUser\My\$($cert.Thumbprint)\" -Force

Write-Host 'SSL certificates generated successfully!' -ForegroundColor Green
Write-Host \"Certificate: $certPath\" -ForegroundColor Yellow
Write-Host \"Private Key: $keyPath\" -ForegroundColor Yellow
"

echo.
echo SSL certificates generated successfully!
echo.