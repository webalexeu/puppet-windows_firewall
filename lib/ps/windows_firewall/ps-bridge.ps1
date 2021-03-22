param(
    [String] $Target,
    [String] $Name,
    [String] $DisplayName,
    [String] $Description,
    $Enabled,
    $Action,
    [String] $Protocol,
    $IcmpType,
    $Profile,
    [String] $Program,
    $Direction,
    [String] $LocalAddress,
    [String] $RemoteAddress,
    [String] $ProtocolType,
    [Int]    $ProtocolCode,
    [String] $LocalPort,
    [String] $RemotePort,
    $EdgeTraversalPolicy,
    $InterfaceType,
    $Service,
    [String] $Authentication,
    [String] $Encryption,
    [String] $LocalUser,
    [String] $RemoteUser,
    [String] $RemoteMachine
)

Import-Module NetSecurity


function Convert-IpAddressToMaskLength([string] $Address)
{
  if ($Address -like '*/*') {
  $Network=$Address.Split('/')[0]
  $SubnetMask=$Address.Split('/')[1]
  $result = 0; 
  # ensure we have a valid IP address
  [IPAddress] $ip = $SubnetMask;
  $octets = $ip.IPAddressToString.Split('.');
  foreach($octet in $octets)
  {
    while(0 -ne $octet) 
    {
      $octet = ($octet -shl 1) -band [byte]::MaxValue
      $result++; 
    }
  }
  return $Network+'/'+$result;
  }
  else {
      return $Address;
  }   
}

# Lookup select firewall rules using powershell. This is needed to resolve names that are missing
# from netsh output
function Show {

    $rules = New-Object System.Collections.ArrayList
    Get-NetFirewallRule | ForEach-Object {

        $af = (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_)[0]
        $appf = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_)[0]
        $pf = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_)[0]
        $if = (Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $_)[0]
        $sf = (Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $_)[0]
        $secf = (Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $_)[0]

        $rules.Add(@{
                Name                = $_.Name
                DisplayName         = $_.DisplayName
                Description         = $_.Description
                Enabled             = $_.Enabled.toString()
                Action              = $_.Action.toString()
                Direction           = $_.Direction.toString()
                EdgeTraversalPolicy = $_.EdgeTraversalPolicy.toString()
                Profile             = $_.Profile.toString()
                DisplayGroup        = $_.DisplayGroup
                # Address Filter
                LocalAddress        = if ($af.LocalAddress -is [object]) { ($af.LocalAddress | ForEach-Object {Convert-IpAddressToMaskLength $_}) -join ","  } else { Convert-IpAddressToMaskLength $af.LocalAddress }
                RemoteAddress       = if ($af.RemoteAddress -is [object]) { ($af.RemoteAddress | ForEach-Object {Convert-IpAddressToMaskLength $_}) -join ","  } else { Convert-IpAddressToMaskLength $af.RemoteAddress }
                # Port Filter (Newer powershell versions return a hash)
                LocalPort           = if ($pf.LocalPort -is [object]) { $pf.LocalPort -join "," } else { $pf.LocalPort }
                RemotePort          = if ($pf.RemotePort -is [object]) { $pf.RemotePort -join "," } else { $pf.RemotePort }
                Protocol            = $pf.Protocol
                IcmpType            = $pf.IcmpType
                # Application Filter
                Program             = $appf.Program
                # Interface Filter
                InterfaceType       = $if.InterfaceType.toString()
                # Service Filter
                Service             = $sf.Service
                # Security Filter
                Authentication      = $secf.Authentication.toString()
                Encryption          = $secf.Encryption.toString()
                LocalUser           = $secf.LocalUser.toString()
                RemoteUser          = $secf.RemoteUser.toString()
                RemoteMachine       = $secf.RemoteMachine.toString()
            }) > $null
    }
    convertto-json $rules
}

function delete {
    write-host "Deleting $($Name)..."

    # rules containing square brackets need to be escaped or nothing will match
    # eg: "Ruby interpreter (CUI) 2.4.3p205 [x64-mingw32]"
    $Name = $name.replace(']', '`]').replace('[', '`[')

    # Depending how rule was parsed (netsh vs ps) `$Name` will contain either
    # `DisplayName` or rule ID. Therefore, delete by Displayname first, if this
    # fails, fallback to `Name` and if this also fails, error the script
    # (`-ErrorAction Stop`)
    if (Get-NetFirewallRule -DisplayName $name -erroraction 'silentlycontinue') {
        remove-netfirewallrule -DisplayName $Name
    }
    elseif (Get-NetFirewallRule -Name $name -erroraction 'silentlycontinue') {
        remove-netfirewallrule -Name $Name -ErrorAction Stop
    }
    else {
        throw "We were told to delete firewall rule '$($name)' but it does not exist"
    }

}


function create {

    $params = @{
        Name        = $Name;
        Enabled     = $Enabled;
        DisplayName = $DisplayName;
        Description = $Description;
        Action      = $Action;
    }

    #
    # general optional params
    #
    if ($Direction) {
        $params.Add("Direction", $Direction)
    }
    if ($EdgeTraversalPolicy) {
        $params.Add("EdgeTraversalPolicy", $EdgeTraversalPolicy)
    }
    if ($Profile) {
        $params.Add("Profile", $Profile)
    }

    #
    # port filter
    #
    if ($Protocol) {
        $params.Add("Protocol", $Protocol)
    }
    if ($ProtocolType) {
        $params.Add("ProtocolType", $ProtocolType)
    }
    if ($ProtocolCode) {
        $params.Add("ProtocolCode", $ProtocolCode)
    }
    if ($IcmpType) {
        $params.Add("IcmpType", $IcmpType)
    }
    # `$LocalPort` and `$RemotePort` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split. The firewall GUI will sort any
    # passed port ranges but the PS API does not
    if ($LocalPort) {
        $params.Add("LocalPort", ($LocalPort -split ','))
    }
    if ($RemotePort) {
        $params.Add("RemotePort", ($RemotePort -split ','))
    }

    #
    # Program filter
    #
    if ($Program) {
        $params.Add("Program", $Program)
    }

    #
    # Interface filter
    #
    if ($InterfaceType) {
        $params.Add("InterfaceType", $InterfaceType)
    }

    # Host filter
    if ($LocalAddress) {
        $params.Add("LocalAddress", ($LocalAddress -split ','))
    }
    if ($RemoteAddress) {
        $params.Add("remoteAddress", ($RemoteAddress -split ','))
    }

    # Service Filter
    if ($Service) {
        $params.Add("Service", $Service)
    }

    # Security Filter
    if ($Authentication) {
        $params.Add("Authentication", $Authentication)
    }
    if ($Encryption) {
        $params.Add("Encryption", $Encryption)
    }
    if ($LocalUser) {
        $params.Add("LocalUser", $LocalUser)
    }
    if ($RemoteUser) {
        $params.Add("RemoteUser", $RemoteUser)
    }
    if ($RemoteMachine) {
        $params.Add("RemoteMachine", $RemoteMachine)
    }

    New-NetFirewallRule @params -ErrorAction Stop
}

function update {
    write-host "Updating $($Name)..."
    $params = @{
        Name = $Name;
    }
    if ($DisplayName) {
        $params.Add("NewDisplayName", $DisplayName)
    }
    if ($Enabled) {
        $params.Add("Enabled", $Enabled)
    }
    if ($Description) {
        $params.Add("Description", $Description)
    }
    if ($Action) {
        $params.Add("Action", $Action)
    }
    #
    # general optional params
    #
    if ($Direction) {
        $params.Add("Direction", $Direction)
    }
    if ($EdgeTraversalPolicy) {
        $params.Add("EdgeTraversalPolicy", $EdgeTraversalPolicy)
    }
    if ($Profile) {
        $params.Add("Profile", $Profile)
    }

    #
    # port filter
    #
    if ($Protocol) {
        $params.Add("Protocol", $Protocol)
    }
    if ($ProtocolType) {
        $params.Add("ProtocolType", $ProtocolType)
    }
    if ($ProtocolCode) {
        $params.Add("ProtocolCode", $ProtocolCode)
    }
    if ($IcmpType) {
        $params.Add("IcmpType", $IcmpType)
    }
    # `$LocalPort` and `$RemotePort` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split. The firewall GUI will sort any
    # passed port ranges but the PS API does not
    if ($LocalPort) {
        $params.Add("LocalPort", ($LocalPort -split ','))
    }
    if ($RemotePort) {
        $params.Add("RemotePort", ($RemotePort -split ','))
    }

    #
    # Program filter
    #
    if ($Program) {
        $params.Add("Program", $Program)
    }

    #
    # Interface filter
    #
    if ($InterfaceType) {
        $params.Add("InterfaceType", $InterfaceType)
    }

    # Host filter
    if ($LocalAddress) {
        $params.Add("LocalAddress", ($LocalAddress -split ','))
    }
    if ($RemoteAddress) {
        $params.Add("remoteAddress", ($RemoteAddress -split ','))
    }

    # Service Filter
    if ($Service) {
        $params.Add("Service", $Service)
    }

    # Security Filter
    if ($Authentication) {
        $params.Add("Authentication", $Authentication)
    }
    if ($Encryption) {
        $params.Add("Encryption", $Encryption)
    }
    if ($LocalUser) {
        $params.Add("LocalUser", $LocalUser)
    }
    if ($RemoteUser) {
        $params.Add("RemoteUser", $RemoteUser)
    }
    if ($RemoteMachine) {
        $params.Add("RemoteMachine", $RemoteMachine)
    }

    if (Get-NetFirewallRule -Name $name -erroraction 'silentlycontinue') {
        Set-NetFirewallRule @params -ErrorAction Stop
    }
    else {
        throw "We were told to update firewall rule '$($name)' but it does not exist"
    }
}

switch ($Target) {
    "show" {
        show
    }
    "delete" {
        delete
    }
    "create" {
        create
    }
    "update" {
        update
    }
    default {
        throw "invalid target: $($Target)"
    }
}