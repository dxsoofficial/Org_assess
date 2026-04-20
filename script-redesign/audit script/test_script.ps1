function Get-InstalledPrograms {
param($regPath)

```
$list = @()

try {
    $baseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath)
    if ($baseKey) {
        foreach ($sub in $baseKey.GetSubKeyNames()) {
            $subKey = $baseKey.OpenSubKey($sub)
            if ($subKey) {
                $name = $subKey.GetValue("DisplayName")
                if ($name) {
                    $list += [PSCustomObject]@{
                        Name    = $name
                        Version = $subKey.GetValue("DisplayVersion")
                    }
                }
            }
        }
    }
} catch {}

return $list
```

}

$apps = @()
$apps += Get-InstalledPrograms "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$apps += Get-InstalledPrograms "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

$apps | Sort-Object Name -Unique | Format-Table
