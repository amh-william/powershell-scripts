$results = @()
$netstat = Invoke-Command -ScriptBlock { netstat -ano }

$netstat[4..$netstat.Length].ForEach({
        $tmp = ($_.trim().split(" ", [System.StringSplitOptions]::RemoveEmptyEntries));
        if ($tmp[4] -eq "Listening" -or -not $tmp[1].contains("[")) {
            if ($tmp[2].Split(':')[0] -Match '(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(0\.0\.0\.0)|(\*)') {
                if ($tmp.Length -eq 5) {
                    $results += [PSCustomObject]@{
                        Proto          = $tmp[0];
                        LocalAddress   = $tmp[1].Split(':')[0];
                        LocalPort      = $tmp[1].Split(':')[1];
                        ForeignAddress = $tmp[2].Split(':')[0];
                        ForeignPort    = $tmp[2].Split(':')[1];
                        Process        = if (-not (Get-Process -Id ([int]($tmp[4]))).Path -eq "") {(Get-Process -Id ([int]($tmp[4]))).Path}  else {((Get-Process -Id ([int]($tmp[4]))).ProcessName)}
                    }
                }
                else {
                    $results += [PSCustomObject]@{
                        Proto          = $tmp[0];
                        LocalAddress   = $tmp[1].Split(':')[0];
                        LocalPort      = $tmp[1].Split(':')[1];
                        ForeignAddress = $tmp[2].Split(':')[0];
                        ForeignPort    = $tmp[2].Split(':')[1];
                        Process        = if (-not (Get-Process -Id ([int]($tmp[3]))).Path -eq "") {(Get-Process -Id ([int]($tmp[3]))).Path}  else {((Get-Process -Id ([int]($tmp[4]))).ProcessName)}
                    }
                }
            }
        }
    })



$results | Export-Csv -Path ".\NetServicesCheck.csv" -NoTypeInformation
