# Print a random 128-hex SECRET_KEY_BASE (64 cryptographically random bytes).
# Used by openc3.bat when .env / .env.local do not provide one.
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 64
$rng.GetBytes($bytes)
Write-Output (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
