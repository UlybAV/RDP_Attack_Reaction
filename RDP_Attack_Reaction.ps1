[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8");

$logsPath = "g:\RDP_Attacks";
$date_format = "dd.MM.yy HH:mm:ss";

$maxCountFails = 8;
$days = 1;

$NameRule = "BlockRDPBruteForce";
$RDPPort = 3389;

$eventAttack = Get-EventLog -LogName Security -newest 1 -InstanceId 4625;

$HashAttackerIp = $eventAttack |Select @{n='IpAddress';e={$_.ReplacementStrings[-2]}};
$ipAttacker = $HashAttackerIp.IpAddress;

# ƒоработать исключени€?
if ($ipAttacker -eq '::1') { exit 0 };

$logAttackerPath = $logsPath + '\' +  $ipAttacker + '\';

mkdir $logAttackerPath;

$countFailsFile = $logAttackerPath + 'count.txt';

$HashLogWriteDate =  Get-ChildItem -Path $countFailsFile |select LastWriteTime;
$logWriteDate = $HashLogWriteDate.LastWriteTime;
$today = Get-Date;

# ”точнить логику возможно.
$passedDays = (New-TimeSpan -Start $logWriteDate -End $today).TotalDays;
if ($passedDays -gt $days) { Del $countFailsFile };

[int]$count = Get-Content $countFailsFile -TotalCount 1;

$count++;
$count > $countFailsFile;

$HashAttackerLogin = $eventAttack |Select @{n='Login';e={$_.ReplacementStrings[-16]}};
$loginAttacker = $HashAttackerLogin.Login;
$EventTime = ($eventAttack |select TimeGenerated).TimeGenerated.ToString($date_format);


$failsFile =  $logAttackerPath + 'fails.txt';
$loginAttacker + '   ' + $EventTime >> $failsFile;

if ($count -gt $maxCountFails) {
##### „”∆јя „ј—“№ #####
# “ут можно сделать запись сразу IP атакующего, а не 1.1.1.1, но тогда дальнейший ход надо ограничить.
    if($null -eq (Get-NetFirewallRule -DisplayName $NameRule -ErrorAction SilentlyContinue)){New-NetFirewallRule -DisplayName "$NameRule" ЦRemoteAddress 1.1.1.1 -Direction Inbound -Protocol TCP ЦLocalPort $RDPPort -Action Block};

    $current_ips = (Get-NetFirewallRule -DisplayName "$NameRule" | Get-NetFirewallAddressFilter ).RemoteAddress -split(',');
    
    $current_ips += $ipAttacker;

#    echo $current_ips;

    Set-NetFirewallRule -DisplayName "$NameRule" -RemoteAddress $current_ips
    #####  ќЌ≈÷ „”∆ќ… „ј—“» #####
}

exit 0