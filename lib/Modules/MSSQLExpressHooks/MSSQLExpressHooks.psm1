# Copyright 2015 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

Import-Module JujuLogging
Import-Module JujuUtils
Import-Module JujuHooks
Import-Module JujuWindowsUtils
Import-Module JujuHelper

try {
    $modulePath = Join-Path ${env:ProgramFiles(x86)} "Microsoft SQL Server\120\Tools\PowerShell\Modules\Sqlps"
    Import-Module $modulePath -DisableNameChecking
} catch {
    Write-JujuWarning "SQL Server not yet installed"
}

# GLOBAL VARIABLES

$INSTANCE_NAME = "SQLEXPRESS"
$SERVICE_NAMES = @(
    "MSSQL`$$INSTANCE_NAME",
    'SQLWriter',
    'SQLBrowser'
)
$DEFAULT_INSTALLER_URL = @{
    '2014' = 'http://download.microsoft.com/download/E/A/E/EAE6F7FC-767A-4038-A954-49B8B05D04EB/Express%2064BIT/SQLEXPR_x64_ENU.exe#sha1=38E0D08F06AF2F907E1AEBDCA0444B828AE356B5'
    '2012' = 'http://download.microsoft.com/download/8/D/D/8DD7BDBA-CEF7-4D8E-8C16-D9F69527F909/ENU/x64/SQLEXPR_x64_ENU.exe#sha1=E4561D5CAA761A5D1DAA0D305F4FECEDC6A0D39C'
}


# MODULE FUNCTIONS

# In order to allow connections to MSSQL database, firewall rules and Juju
# ports must be open. This function adds, via netsh.exe, required Windows
# firewall rules for the MSSQL processes and it opens all TCP and UDP
# ports.
function Open-MSSQLPorts {
    $sqlservrPath = (Get-Process 'sqlservr').Path
    $sqlbrowserPath = (Get-Process 'sqlbrowser').Path

    Start-ExternalCommand -ScriptBlock {
        netsh.exe advfirewall firewall add rule name="SQLSERVR" `
                  dir=in action=allow program=$sqlservrPath enable=yes
    } -ErrorMessage "Failed to add firewall rule for sqlservr"
    Start-ExternalCommand -ScriptBlock {
        netsh.exe advfirewall firewall add rule name="SQLBROWSER" `
                  dir=in action=allow program=$sqlbrowserPath enable=yes
    } -ErrorMessage "Failed to add firewall rule for sqlbrowser"

    $ports = @{
      "tcp" = @(1433, 1434, 443, 5022);
      "udp" = @(1433, 1434, 5022)
    }

    foreach($i in $ports.Keys) {
        foreach($p in $ports[$i]) {
            Open-JujuPort ("{0}/{1}" -f @($p, $i))
        }
    }
}

# Presence of the core SQL Server files for a specific version indicates
# that the service is already installed
function Get-IsMSSQLInstalled {
    Param(
        [Parameter(Mandatory=$true)]
        [int]$Version
    )

    return (Get-ComponentIsInstalled "SQL Server $Version Common Files")
}

function Get-MSSQLInstaller {
    $version = Get-JujuCharmConfig -scope 'version'
    $installerUrl = Get-JujuCharmConfig -Scope 'installer-url'
    if(!$installerUrl) {
        # Use default installer
        $installerUrl = $DEFAULT_INSTALLER_URL["$version"]
    }

    Write-JujuLog "Downloading MSSQL installer from: $installerUrl"

    $installerPath = Join-Path $env:TEMP "SQLEXPR_x64_ENU.exe"
    Start-ExecuteWithRetry {
        Invoke-FastWebRequest -Uri $installerUrl -OutFile $installerPath | Out-Null
    } -RetryMessage "Downloading installer failed. Retrying..."

    return $installerPath
}

# During the MSSQL setup, an additional 'NET-Framework-Core' Windows feature
# will be installed as this is required for SQL Server. The MSSQL services
# will run under a Windows user that will be created before running the
# installer. The installer is downloaded from the Internet and check for
# integrity using SHA1 checksum.
function Install-MSSQLExpress {
    $version = Get-JujuCharmConfig -scope "version"
    if ($version -notin $DEFAULT_INSTALLER_URL.Keys) {
        throw "Unsupported MSSQL Express version"
    }

    Write-JujuWarning "Installing NET-Framework-Core Windows Feature ..."
    Start-ExecuteWithRetry {
        Install-WindowsFeatures @('NET-Framework-Core')
    }

    if (Get-IsMSSQLInstalled -Version $version) {
        Write-JujuWarning "MSSQL Express already installed"
        Open-MSSQLPorts
        return
    }

    $serviceUsername = "SQLEXPRESS"
    $serviceUserPassword = Get-RandomString -Length 10 -Weak
    Add-WindowsUser $serviceUsername $serviceUserPassword

    $features = "SQL,Tools"
    $saPassword = Get-JujuCharmConfig -scope "sa-password"
    $parameters = @(
        "/ACTION=Install",
        "/Q",
        "/IACCEPTSQLSERVERLICENSETERMS",
        "/INSTANCENAME=$INSTANCE_NAME",
        "/UpdateEnabled=0",
        "/NPENABLED=1",
        "/TCPENABLED=1"
        "/ERRORREPORTING=1",
        "/SECURITYMODE=SQL"
        "/SAPWD=$saPassword",
        "/FEATURES=$features",
        "/SQLSYSADMINACCOUNTS=.\jujud",
        "/AGTSVCSTARTUPTYPE=Automatic",
        "/BROWSERSVCSTARTUPTYPE=Automatic",
        "/SQLSVCSTARTUPTYPE=Automatic",
        "/SQLSVCACCOUNT=.\$serviceUsername",
        "/SQLSVCPASSWORD=$serviceUserPassword"
    )
    $installerPath = Get-MSSQLInstaller

    Write-JujuWarning "Started installing MSSQL Express $version ..."

    $stat = Start-Process -FilePath $installerPath -ArgumentList $parameters `
                          -PassThru -Wait
    if ($stat.ExitCode -ne 0) {
        throw "MSSQL Express $version failed to install"
    }
    Remove-Item $installerPath
    Open-MSSQLPorts

    Write-JujuWarning "Finished installing MSSQL Express"
}

function Get-SqlDatabase {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Database
    )

    $namespace = "SQLSERVER:\sql\{0}\$INSTANCE_NAME\Databases" -f @($env:COMPUTERNAME)
    $db = (Get-ChildItem $namespace | Where-Object {$_.Name -eq $Database})
    if($db) {
        return $db
    }
    Throw [System.Management.Automation.ItemNotFoundException] "No such database: $Database"
}

function New-SQLDatabase {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Database,
        [Parameter(Mandatory=$false)]
        [string]$Collation="Latin1_General_CI_AS_KS_WS"
    )

    try {
        $db = Get-SqlDatabase -Database $Database
        return $db
    } catch [System.Management.Automation.ItemNotFoundException]{
        Write-JujuWarning "Creating new database: $Database"
    }

    $instance = "{0}\$INSTANCE_NAME" -f @($env:COMPUTERNAME)
    $sqlSrv = New-Object Microsoft.SqlServer.Management.Smo.Server $instance
    $db = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Database($sqlSrv, $Database)
    $db.Collation = $Collation
    $db.Create()
    $db.Refresh()

    return $db
}

function Get-MSSQLLogin {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [switch]$UseSACreds=$false
    )

    $instance = ("{0}\$INSTANCE_NAME" -f @($env:COMPUTERNAME))
    $sqlSrv = New-Object Microsoft.SqlServer.Management.Smo.Server $instance
    if($UseSACreds) {
        $sqlSrv.ConnectionContext.LoginSecure = $false
        $sqlSrv.ConnectionContext.Login = "sa"
        $sqlSrv.ConnectionContext.Password = Get-JujuCharmConfig -Scope "sa-password"
    }
    $sqlSrv.Refresh()
    $login = $sqlSrv.Logins | Where-Object {$_.Name -eq $Username}
    if($login) {
        return $login
    }
    return $null
}

function New-MSSQLLogin {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [string]$Password,
        [Parameter(Mandatory=$false)]
        [ValidateSet("WindowsUser", "SqlLogin")]
        [Microsoft.SqlServer.Management.Smo.LoginType]$LoginType="WindowsUser",
        [Parameter(Mandatory=$false)]
        [array]$Roles=@("securityadmin", "dbcreator"),
        [Parameter(Mandatory=$false)]
        [switch]$UseSACreds=$false,
        [Parameter(Mandatory=$false)]
        [byte[]]$Sid
    )

    if($LoginType -eq "SqlLogin" -and !$Password){
        Throw "Password parameter is required for SqlLogin"
    }

    $instance = ("{0}\$INSTANCE_NAME" -f @($env:COMPUTERNAME))
    $sqlSrv = New-Object Microsoft.SqlServer.Management.Smo.Server $instance
    if($UseSACreds) {
        $sqlSrv.ConnectionContext.LoginSecure = $false
        $sqlSrv.ConnectionContext.Login = "sa"
        $sqlSrv.ConnectionContext.Password = Get-JujuCharmConfig -Scope "sa-password"
    }
    $sqlSrv.Refresh()
    $login = $sqlSrv.Logins | Where-Object {$_.Name -eq $Username}
    if($login) {
        return $login
    }

    $login = New-Object Microsoft.SqlServer.Management.Smo.Login $sqlSrv, $Username
    $login.LoginType = $LoginType
    if($LoginType -eq "WindowsUser") {
        $login.Create()
    } else {
        $login.PasswordExpirationEnabled = $false
        if($Sid) {
            $login.Sid = $Sid
        }
        $login.Create($Password)
    }

    foreach($i in $Roles) {
        Write-JujuWarning "Adding role $i to $Username"
        if($i -eq "sysadmin" -and $login.DefaultDatabase -ne "master") {
            $login.DefaultDatabase = "master"
        }
        $login.AddToRole($i)
        $login.Alter()
        $login.Refresh()
    }
    return $login
}

function Grant-AccessToDatabase {
    Param(
        [Parameter(Mandatory=$true)]
        [Microsoft.SqlServer.Management.Smo.Login]$Login,
        [Parameter(Mandatory=$true)]
        [Microsoft.SqlServer.Management.Smo.Database]$Database,
        [Parameter(Mandatory=$false)]
        [switch]$MakeOwner=$true,
        [Parameter(Mandatory=$false)]
        [ValidateSet("db_accessadmin",
                     "db_backupoperator",
                     "db_datareader",
                     "db_datawriter",
                     "db_ddladmin",
                     "db_denydatareader",
                     "db_denydatawriter",
                     "db_owner",
                     "db_securityadmin")]
        [array]$Roles=@("db_datareader","db_datawriter","db_ddladmin", "db_securityadmin", "db_owner")
    )

    $name = $Login.Name
    if($MakeOwner -and $Database.Users["dbo"].Login -ne $name) {
        $Database.SetOwner($name, "True")
        $Database.Alter()
        return
    }
    if($Database.Users["dbo"].Login -eq $name) {
        Write-JujuWarning "User is already DB owner"
        return
    }
    Write-JujuWarning ("Users: {0}" -f ($Database.Users -Join " "))
    $exists = $Database.Users | Where-Object {$_.Name -eq $name}
    if($exists) {
        return $exists
    }
    $user = New-Object Microsoft.SqlServer.Management.Smo.User $Database, $name
    $user.Login = $name
    $user.Create()
    foreach($i in $Roles) {
        $user.AddToRole($i)
    }
    $user.Alter()
    $user.Refresh()
    return $user
}


# HOOKS FUNCTIONS

function Invoke-InstallHook {
    Install-MSSQLExpress
}

function Invoke-ConfigChangedHook {
    if(!(Confirm-Leader)) {
        Write-JujuWarning "Current unit is not leader"
        return
    }

    $saPassword = Get-JujuCharmConfig -Scope 'sa-password'
    $currentSaPassword = Get-LeaderData -Attribute 'sa-pass'
    if($saPassword -eq $currentSaPassword) {
        Write-JujuWarning "SA password is already set to the current config value"
        return
    }

    $instance = ("{0}\$INSTANCE_NAME" -f @($env:COMPUTERNAME))
    $sqlSrv = New-Object Microsoft.SqlServer.Management.Smo.Server $instance
    $sqlSrv.Refresh()
    $login = $sqlSrv.Logins | Where-Object {$_.Name -eq "sa"}
    $login.ChangePassword($saPassword)

    Set-LeaderData -Settings @{
        'sa-pass' = $saPassword
    }
}

function Invoke-StopHook {
    foreach ($service in $SERVICE_NAMES) {
        Stop-Service -Name $service
        Set-Service -Name $service -StartupType Manual
    }
}

function Invoke-SharedDBRelationChangedHook {
    $dbName = Get-JujuRelation 'database'
    $dbUser = Get-JujuRelation 'user'
    if (!$dbName -and !$dbUser) {
        Write-JujuWarning ("Database name and user name are not set by remote charm. Skipping")
        return
    }

    $db = New-SQLDatabase -Database $dbName
    $login = Get-MSSQLLogin -Username $dbUser
    if(!$login) {
        $dbUserPassword = Get-RandomString -Length 10 -Weak
        $login = New-MSSQLLogin -LoginType 'SqlLogin' -Username $dbUser -Password $dbUserPassword
        if(Confirm-Leader) {
            Set-LeaderData -Settings @{
                "${dbUser}-pass" = $dbUserPassword
            }
        }
    }

    if(Confirm-Leader) {
        Grant-AccessToDatabase -Login $login -Database $db
    }

    $loginPassword = Get-LeaderData -Attribute "${dbUser}-pass"
    if($loginPassword) {
        $relationSettings = @{
            'database' = $dbName
            'instance' = $INSTANCE_NAME
            'user' = $dbUser
            'password' = $loginPassword
        }
        Set-JujuRelation -Settings $relationSettings
    }
}
