#Requires -RunAsAdministrator
Set-ExecutionPolicy bypass

clear
Write-Host 'Powershell version=' $PsVersionTable.PSVersion 
Get-Date
Write-Host "!!! It is highly recommend to run this script after memory image capture process."  -ForegroundColor red -BackgroundColor white
Write-Host ""
Write-Host "!!! Save event logs to another disk or location."  -ForegroundColor red -BackgroundColor white
Write-Host ""
Write-Host "!!! Folder location to save event logs (It will create a new directory if the path does not exist, exp: D:\testlogs)"  -ForegroundColor red -BackgroundColor white
Write-Host ""


$path = Read-Host 
If(!(test-path $path))
{
      New-Item -ItemType Directory -Force -Path $path
}

 
Write-Host "Collecting Event Logs..." -ForegroundColor red -BackgroundColor white
 
$securityEventList= 4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4741,4742,4743,4754,4755,4756,4757,4758,4798,4799,4768,4769,4770,4771,4776,4624,4625,4634,4647,4648,4672,4778,4779,5140,5142,5143,5144,5145,4698,4699,4700,4701,4702,4656,4657,4658,4660,4663,4719,1102,4688,5031,5152,5154,5156,5157,5158,5159
$i=0;
foreach ($eventId in $securityEventList)
    {
      $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($securityEventList.Count)" -percentComplete (($i / $securityEventList.Count)  * 100)
   try {
      Get-WinEvent -FilterHashTable @{LogName='Security';ID=$eventId} -ErrorAction Stop | fl  >> $path\security.txt  }
     
     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
          {Out-Null}
         }
     }

Get-FileHash  $path\security.txt -Algorithm SHA256 | fl > $path\hashes.txt
$i=0;     
$systemEventList= 6005,6006,7034,7036,7040,7045
foreach ($systemEventId in $systemEventList)
    {
     $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($systemEventList.Count)" -percentComplete (($i / $systemEventList.Count)  * 100)
     try {  Get-WinEvent -FilterHashTable @{LogName='System';ID=$systemEventId} -ErrorAction Stop | fl  >> $path\system.txt   }

     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
          {Out-Null}
         }
     }

Get-FileHash  $path\system.txt -Algorithm SHA256 | fl >> $path\hashes.txt
$i=0; 
$taskschEventList=106,140,141,200,201
foreach ($taskEventId in $taskschEventList)
    {
     $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($taskschEventList.Count)" -percentComplete (($i / $taskschEventList.Count)  * 100)
     try {   Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-TaskScheduler/Operational';ID=$taskEventId} -ErrorAction Stop | fl  >> $path\taskscheduler.txt   }

     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
          {Out-Null}
         }
     }
Get-FileHash  $path\taskscheduler.txt -Algorithm SHA256 | fl >> $path\hashes.txt
$i=0; 
$wirelessEventList= 8001,8002
foreach ($wirelessEventId in $wirelessEventList)
    {
     $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($wirelessEventList.Count)" -percentComplete (($i / $wirelessEventList.Count)  * 100)
     try {  Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';ID=$wirelessEventId} -ErrorAction Stop | fl    >> $path\wireless.txt  }

     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
          {Out-Null}
         }
     }

Get-FileHash  $path\wireless.txt -Algorithm SHA256 | fl >> $path\hashes.txt
$i=0; 
$defenderEventList= 1006,1007,1008,1013,1015,1116,117,118,1119,5001,5004,5007,5010,5012
foreach ($defenderEventId in $defenderEventList)
    {
     $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($defenderEventList.Count)" -percentComplete (($i / $defenderEventList.Count)  * 100)
     try {  Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Windows Defender/Operational';ID=$defenderEventId} -ErrorAction Stop | fl  >> $path\defender.txt }

     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
          {Out-Null}
         }
     }

Get-FileHash  $path\defender.txt -Algorithm SHA256 | fl >> $path\hashes.txt
$i=0;      
$sysmonEventList= 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,255
foreach ($sysmonEventId in $sysmonEventList)
    {
     $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($sysmonEventList.Count)" -percentComplete (($i / $sysmonEventList.Count)  * 100)
     try {  Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=$sysmonEventId} -ErrorAction Stop | fl  >> $path\sysmon.txt  }

     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
          {Out-Null}
         }
     }   

Get-FileHash  $path\sysmon.txt -Algorithm SHA256 | fl >> $path\hashes.txt
$i=0; 
$powershellEventList= 4103,4104,400,800
foreach ($powershellEventId in $powershellEventList)
    {
     $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($powershellEventList.Count)" -percentComplete (($i / $powershellEventList.Count)  * 100)
     try {  Get-WinEvent -FilterHashTable @{LogName='Microsoft-Windows-Powershell/Operational';ID=$powershellEventList} -ErrorAction Stop | fl  >> $path\powershell.txt   }

     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
          {Out-Null}
         }
     }
Get-FileHash  $path\powershell.txt -Algorithm SHA256 | fl >> $path\hashes.txt

Write-Host "Event logs are collected. Check files and hashes."  -ForegroundColor red -BackgroundColor white
Sleep 10