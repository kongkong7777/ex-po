
Set-Location (Get-Item ($MyInvocation.MyCommand.Definition)).DirectoryName

$MinutesToBack = 1

$Date = Get-Date
$strDate = $Date.ToString('yyyy-MM-dd')

$End_time = $Date
$Start_time = $Date.AddMinutes(-$MinutesToBack)
$LogFolder = '.\Logs'
$strLogFile = "$LogFolder\${strDate}.txt"
$strLogFile_e = "$LogFolder\${strDate}_e.txt"

Set-Content -Path $strLogFile_e -Value $null

$WhiteList = @(Get-Content -Path 'FW_WhiteList.txt' -ErrorAction:SilentlyContinue | ?{$_ -and $_ -imatch '^[^#]'})
$BlackList = @(Get-Content -Path 'FW_BlackList.txt' -ErrorAction:SilentlyContinue | ?{$_ -and $_ -imatch '^[^#]'})

$t_4625_fw = @(30, 1)
$t_4625_fw_Intranet = @(50, 3)
$t_4625_fw_Timeout = 30

$Mail_From = "$($env:COMPUTERNAME)<ITInfraAlerts@didichuxing.com>"
$Mail_To = 'linbinbin@didichuxing.com', 'wangliang@didichuxing.com', 'songlong@didichuxing.com', 'guoshuo@didichuxing.com', 'zhangningnik@didichuxing.com'
$Mail_Subject = 'IP验证告警'

$Mail_SMTPServer = 'mail.didichuxing.com'

function Add-Log
{
    PARAM(
        [String]$Path,
        [String]$Value,
        [String]$Type = 'Info'
    )
    $Type = $Type.ToUpper()
    $Date = Get-Date
    Write-Host "$($Date.ToString('[HH:mm:ss] '))[$Type] $Value" -ForegroundColor $(
        switch($Type)
        {
            'WARNING' {'Yellow'}
            'Error' {'Red'}
            default {'White'}
        }
    )
    if($Path){
        Add-Content -LiteralPath $Path -Value "$($Date.ToString('[HH:mm:ss] '))[$Type] $Value" -ErrorAction:SilentlyContinue
    }
}

Add-Log -Path $strLogFile_e -Value "Catch logs after : $($Start_time.ToString('HH:mm:ss'))"
Add-Log -Path $strLogFile_e -Value "Catch logs before: $($End_time.ToString('HH:mm:ss'))"

$4625 = @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4625; StartTime = $Start_time; EndTime = $End_time;} -ErrorAction:SilentlyContinue)
Add-Log -Path $strLogFile_e -Value "Total 4625 logs count : [$($4625.Count)]"

# http://schemas.microsoft.com/win/2004/08/events/event
# index 5 = TargetUserName
# index 6 = TargetDomainName
# index 19 = IpAddress
$s_4625 = @{}
foreach($e in $4625)
{
    $xmlData = $IP = $Account = $Domain = $null
    $xmlData = [xml]$e.ToXml()
    $IP = $(
        if($xmlData.Event.EventData.Data[19].'#text' -imatch '^\s*$')
        {
            '(NULL)'
        }
        else
        {
            $xmlData.Event.EventData.Data[19].'#text'.Trim()
        }
    )
    $Account = $(
        if($xmlData.Event.EventData.Data[5].'#text' -imatch '^\s*$')
        {
            '(NULL)'
        }
        else
        {
            $xmlData.Event.EventData.Data[5].'#text'.Trim()
        }
    )
    $Domain = $(
        if($xmlData.Event.EventData.Data[6].'#text' -imatch '^\s*$')
        {
            '(NULL)'
        }
        else
        {
            $xmlData.Event.EventData.Data[6].'#text'.Trim()
        }
    )
    if($Account -notmatch '@|\\')
    {
        $Account = "$Domain\$Account"
    }
    $s_4625.$($IP) += @($Account)
}

$GoBlock = @()
foreach($IP in $s_4625.Keys)
{
    $tmp = @($s_4625.$IP | Group-Object | Sort-Object Count -Descending)
    Add-Log -Path $strLogFile_e -Value "过去[${MinutesToBack}]分钟[IP地址][错误量][账户][前5]:[$IP][$($s_4625.$IP.Count)][$($tmp.Count)][$($tmp[0..4] | %{$_.Name, $_.Count -join ':'})]"
    $tmpx = @($WhiteList | ?{$IP -imatch $_})
    if($tmpx)
    {
        Add-Log -Path $strLogFile_e -Value "[$IP] in white list, matched: [$($tmpx -join '][')]"
        if($tmpx -imatch 'supper')
        {
            Add-Log -Path $strLogFile_e -Value "[$IP] 匹配到超级白名单条目,跳过白名单阈值检测"
            continue
        }
        if($s_4625.$IP.Count -ge $t_4625_fw_Intranet[0] -and $tmp.Count -ge $t_4625_fw_Intranet[1])
        {
            Add-Log -Path $strLogFile_e -Value "[$IP] 在白名单当中,但是超过了白名单阈值,加入防火墙队列" -Type Warning
            $GoBlock += $IP
        }
    }
    else
    {
        Add-Log -Path $strLogFile_e -Value "[$IP] not in white list"
        if($s_4625.$IP.Count -ge $t_4625_fw[0] -and $tmp.Count -ge $t_4625_fw[1])
        {
            $tmp.Name | Add-Content -Path "$LogFolder\$IP.log" -Encoding Default
            Add-Log -Path $strLogFile_e -Value "[$IP] 超过阈值,加入防火墙队列"
            $GoBlock += $IP
        }
    }
}

$Mail = $false
if($GoBlock)
{
    foreach($IP in $GoBlock)
    {
        if(!(Get-NetFirewallRule -DisplayName "ScriptAuto_Block_$IP" -ErrorAction:SilentlyContinue))
        {
            $Mail = $true
            New-NetFirewallRule -DisplayName "ScriptAuto_Block_$IP" -Profile Any -Action Block -RemoteAddress $IP -Direction Inbound -Description $Date.AddMinutes($t_4625_fw_Timeout).ToString('yyyy-MM-dd HH:mm:ss') -ErrorAction:SilentlyContinue
            if(!$?)
            {
                Add-Log -Path $strLogFile_e -Value "[$IP] 加入firewall失败,原因:" -Type Error
                Add-Log -Path $strLogFile_e -Value $Error[0] -Type Error
            }
            else
            {
                Add-Log -Path $strLogFile_e -Value "[$IP] 加入防火墙成功" -Type Warning
            }
        }
    }
}

Get-NetFirewallRule -DisplayName "ScriptAuto_*" | %{
    if($_.Description)
    {
        if(([datetime]($_.Description) - $Date).TotalMinutes -lt 0)
        {
            $_ | Remove-NetFirewallRule
        }
    }
    else
    {
        $_ | Remove-NetFirewallRule
    }
}

$BlackList | %{
    if(!(Get-NetFirewallRule -DisplayName "ScriptAuto_BlackList_$_" -ErrorAction:SilentlyContinue))
    {
        New-NetFirewallRule -DisplayName "ScriptAuto_BlackList_$_" -Profile Any -Action Block -RemoteAddress $_ -Direction Inbound -Description ($Date.AddYears(100).ToString('yyyy-MM-dd HH:mm:ss')) -ErrorAction:SilentlyContinue
    }
}

If($Mail)
{
    try
    {
        Send-MailMessage -From $Mail_From -To $Mail_To -Subject $Mail_Subject -SmtpServer $Mail_SMTPServer -Body ((Get-Content $strLogFile_e -Encoding Default) -join "`t`n") -Encoding utf8
    }
    catch
    {
        Add-Log -Path $strLogFile_e -Value "Failed to send mail, cause: $($Error[0])" -Type Error
    }
}

Get-Content -Path $strLogFile_e | Add-Content -Path $strLogFile
Add-Log -Path $strLogFile_e -Value 'Completed'
