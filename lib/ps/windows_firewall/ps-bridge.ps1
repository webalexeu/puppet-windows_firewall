###############################################################################################
#                                                                                             #
#   Name            PS-Bridge                                                                 #
#                                                                                             #
#   Description     Powershell bridge with Puppet                                             #
#                                                                                             #
#                                                                                             #
#   LicenseUri      https://github.com/webalexeu/puppet-windows_firewall/blob/master/LICENSE  #
#   ProjectUri      https://github.com/webalexeu/puppet-windows_firewall                      #
#                                                                                             #
###############################################################################################

param(
    [String] $Target,
    [String] $Name,
    [String] $DisplayName,
    $Enabled,
    $Action,
    [String] $Protocol,
    $IcmpType,
    $Profile,
    [String] $Program,
    $Direction,
    [String] $Description,
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

# Import required module
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

# Lookup select firewall rules using powershell.
function Show {
    $rules = New-Object System.Collections.ArrayList

    # Firewall rules query (InstanceID is the unique key)
    $firewallRules = Get-NetFirewallRule | Select-Object InstanceID, Name, DisplayName, Description, Enabled, Action, Direction, EdgeTraversalPolicy, Profile, DisplayGroup
    # Querying Firewall rules filter in one query (Parsing for each rule is cpu/time consuming)
    $af_rules = Get-NetFirewallAddressFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|FirewallRule|*'} | Select-Object InstanceID, LocalAddress, RemoteAddress
    $appf_rules = Get-NetFirewallApplicationFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|FirewallRule|*'} | Select-Object InstanceID, Program
    $pf_rules = Get-NetFirewallPortFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|FirewallRule|*'} | Select-Object InstanceID, LocalPort, RemotePort, Protocol, IcmpType
    $if_rules = Get-NetFirewallInterfaceTypeFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|FirewallRule|*'} | Select-Object InstanceID, InterfaceType
    $sf_rules = Get-NetFirewallServiceFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|FirewallRule|*'} | Select-Object InstanceID, Service
    $secf_rules = Get-NetFirewallSecurityFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|FirewallRule|*'} | Select-Object InstanceID, Authentication, Encryption, LocalUser, RemoteUser, RemoteMachine

    # Parse all firewall rules (Using foreach to improve performance)
    ForEach ($firewallRule in $firewallRules) {
        ## Parsing using foreach to improve performance
        $InstanceID=$firewallRule.InstanceID
        ForEach ($af_rule in $af_rules) {if ($af_rule.InstanceID -eq $InstanceID) {$af=$af_rule}}
        ForEach ($appf_rule in $appf_rules) {if ($appf_rule.InstanceID -eq $InstanceID) {$appf=$appf_rule}}
        ForEach ($pf_rule in $pf_rules) {if ($pf_rule.InstanceID -eq $InstanceID) {$pf=$pf_rule}}
        ForEach ($if_rule in $if_rules) {if ($if_rule.InstanceID -eq $InstanceID) {$if=$if_rule}}
        ForEach ($sf_rule in $sf_rules) {if ($sf_rule.InstanceID -eq $InstanceID) {$sf=$sf_rule}}
        ForEach ($secf_rule in $secf_rules) {if ($secf_rule.InstanceID -eq $InstanceID) {$secf=$secf_rule}}

        # Creating Rule Hash
        $rules.Add(@{
                Name                = $firewallRule.Name
                DisplayName         = $firewallRule.DisplayName
                Description         = $firewallRule.Description
                Enabled             = $firewallRule.Enabled.toString()
                Action              = $firewallRule.Action.toString()
                Direction           = $firewallRule.Direction.toString()
                EdgeTraversalPolicy = $firewallRule.EdgeTraversalPolicy.toString()
                Profile             = $firewallRule.Profile.toString()
                # If display group is empty, return 'None' (Required for windows_firewall_group)
                DisplayGroup        = if ($null -ne $firewallRule.DisplayGroup) { $firewallRule.DisplayGroup } else { 'None' }
                # Address Filter (Newer powershell versions return a hash) - Return are sorted to be displayed properly in resources output
                LocalAddress        = if ($af.LocalAddress -is [object]) { ($af.LocalAddress | ForEach-Object {Convert-IpAddressToMaskLength $_} | Sort-Object) } else { Convert-IpAddressToMaskLength $af.LocalAddress.toString() }
                RemoteAddress       = if ($af.RemoteAddress -is [object]) { ($af.RemoteAddress | ForEach-Object {Convert-IpAddressToMaskLength $_} | Sort-Object) } else { Convert-IpAddressToMaskLength $af.RemoteAddress.toString() }
                # Port Filter (Newer powershell versions return a hash) - Return are sorted to be displayed properly in resources output
                LocalPort           = if ($pf.LocalPort -is [object]) { $pf.LocalPort | Sort-Object } else { $pf.LocalPort.toString() }
                RemotePort          = if ($pf.RemotePort -is [object]) { $pf.RemotePort | Sort-Object } else { $pf.RemotePort.toString() }
                Protocol            = $pf.Protocol
                # Do not sort as sorting is already done in the object provided
                IcmpType            = if ($pf.IcmpType -is [object]) { $pf.IcmpType } else { $pf.IcmpType.toString() }
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
    write-host "Deleting $Name"

    # rules containing square brackets need to be escaped or nothing will match
    $Name = $name.replace(']', '`]').replace('[', '`[')

    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -Name $Name -ErrorAction Stop
    }
    else {
        throw "We were told to delete firewall rule '$($name)' but it does not exist"
    }
}


function create {
    write-host "Creating $Name"

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
    # `$IcmpType, `$LocalPort` and `$RemotePort` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split
    if ($IcmpType) {
        $params.Add("IcmpType", ($IcmpType -split ','))
    }
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
    # `$LocalAddress` and `$RemoteAddress` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split
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
    write-host "Updating $Name"

    # rules containing square brackets need to be escaped or nothing will match
    $Name = $name.replace(']', '`]').replace('[', '`[')

    $params = @{
        Enabled        = $Enabled;
        NewDisplayName = $DisplayName;
        Description    = $Description;
        Action         = $Action;
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
    # `$IcmpType, `$LocalPort` and `$RemotePort` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split
    if ($IcmpType) {
        $params.Add("IcmpType", ($IcmpType -split ','))
    }
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
    # `$LocalAddress` and `$RemoteAddress` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split
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

    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $name @params -ErrorAction Stop
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

# SIG # Begin signature block
# MIIoiAYJKoZIhvcNAQcCoIIoeTCCKHUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCEXwnIKgUZlRKK
# ziVPaA3akx9/LAzGEYSpmLWRE8EcoKCCILwwggXJMIIEsaADAgECAhAbtY8lKt8j
# AEkoya49fu0nMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
# ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5l
# dHdvcmsgQ0EwHhcNMjEwNTMxMDY0MzA2WhcNMjkwOTE3MDY0MzA2WjCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMb
# Q2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvfl4+ObVgAxknYYblmRnPyI6HnUBfe/7XGeMycxca6mR5rlC
# 5SBLm9qbe7mZXdmbgEvXhEArJ9PoujC7Pgkap0mV7ytAJMKXx6fumyXvqAoAl4Va
# qp3cKcniNQfrcE1K1sGzVrihQTib0fsxf4/gX+GxPw+OFklg1waNGPmqJhCrKtPQ
# 0WeNG0a+RzDVLnLRxWPa52N5RH5LYySJhi40PylMUosqp8DikSiJucBb+R3Z5yet
# /5oCl8HGUJKbAiy9qbk0WQq/hEr/3/6zn+vZnuCYI+yma3cWKtvMrTscpIfcRnNe
# GWJoRVfkkIJCu0LW8GHgwaM9ZqNd9BjuiMmNF0UpmTJ1AjHuKSbIawLmtWJFfzcV
# WiNoidQ+3k4nsPBADLxNF8tNorMe0AZa3faTz1d1mfX6hhpneLO/lv403L3nUlbl
# s+V1e9dBkQXcXWnjlQ1DufyDljmVe2yAWk8TcsbXfSl6RLpSpCrVQUYJIP4ioLZb
# MI28iQzV13D4h1L92u+sUS4Hs07+0AnacO+Y+lbmbdu1V0vc5SwlFcieLnhO+Nqc
# noYsylfzGuXIkosagpZ6w7xQEmnYDlpGizrrJvojybawgb5CAKT41v4wLsfSRvbl
# jnX98sy50IdbzAYQYLuDNbdeZ95H7JlI8aShFf6tjGKOOVVPORa5sWOd/7cCAwEA
# AaOCAT4wggE6MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLahVDkCw6A/joq8
# +tT4HKbROg79MB8GA1UdIwQYMBaAFAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1Ud
# DwEB/wQEAwIBBjAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLmNlcnR1bS5w
# bC9jdG5jYS5jcmwwawYIKwYBBQUHAQEEXzBdMCgGCCsGAQUFBzABhhxodHRwOi8v
# c3ViY2Eub2NzcC1jZXJ0dW0uY29tMDEGCCsGAQUFBzAChiVodHRwOi8vcmVwb3Np
# dG9yeS5jZXJ0dW0ucGwvY3RuY2EuY2VyMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQG
# CCsGAQUFBwIBFhhodHRwOi8vd3d3LmNlcnR1bS5wbC9DUFMwDQYJKoZIhvcNAQEM
# BQADggEBAFHCoVgWIhCL/IYx1MIy01z4S6Ivaj5N+KsIHu3V6PrnCA3st8YeDrJ1
# BXqxC/rXdGoABh+kzqrya33YEcARCNQOTWHFOqj6seHjmOriY/1B9ZN9DbxdkjuR
# mmW60F9MvkyNaAMQFtXx0ASKhTP5N+dbLiZpQjy6zbzUeulNndrnQ/tjUoCFBMQl
# lVXwfqefAcVbKPjgzoZwpic7Ofs4LphTZSJ1Ldf23SIikZbr3WjtP6MZl9M7JYjs
# NhI9qX7OAo0FmpKnJ25FspxihjcNpDOO16hO0EoXQ0zF8ads0h5YbBRRfopUofbv
# n3l6XYGaFpAP4bvxSgD5+d2+7arszgowggaVMIIEfaADAgECAhAJxcz4u2Z9cTeq
# wVmABssxMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhB
# c3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBUaW1lc3Rh
# bXBpbmcgMjAyMSBDQTAeFw0yMzExMDIwODMyMjNaFw0zNDEwMzAwODMyMjNaMFAx
# CzAJBgNVBAYTAlBMMSEwHwYDVQQKDBhBc3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4x
# HjAcBgNVBAMMFUNlcnR1bSBUaW1lc3RhbXAgMjAyMzCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALkWuurG532SNqqCQCjzkjK3p5w3fjc5Y/O004WQ5G+x
# zq6SG5w45BD6zPEfSOyLcBGMHAbVv2hDCcPHUI46Q6nCbYfNjbPG0l7ZfaoL4fwM
# y3j6dQ0BgW4wQyNF6rmm0NMjcmJ0MRuBzEp2vZrN8LCYncWmoakqvUtu0IPZjuIu
# vBk7E4OR1VgoTIkvRQ8nYDXwmA1Hnj4JnT+lV8J9s4RlqDrmjJTcDfdljzyHmaHO
# f1Yg8X+otHmq30cp727xj64yDPwwpBqAf9qNYb+5hyp5ArbwBLcSHkBxLCXjEV/A
# cZoXATHEFZJctlEZRuf1oV2KtJkop17bSnUI6WZmTEiYlj5vFBhKDDmcQzSM+Dqt
# 48P7QhBBzgA8rp1IcA5BLdC8Emt/NNaUJCiQa06/Fw0izlw69oA2ZNwZwuCQfR4e
# AwGksWVzLMTRCRjwd6H7GW1kUSIC8rmBufwIezyij2jT8mMup1ZgutbgecRLjf80
# LX+w5oJWa2yVNoWhb9ZFFu0lpGsr/TeMWOs33bV0Ke1FGKcH8TDcxDWTE83rThYI
# x4u8A6lPcXkpsFeg8Osyhb04ZNidiq/zwDqFNtUVGz4SLxQmOTgiV86ScdZ26KZE
# pDgtgNjUYNIDfdhRn9zc+ii1qdzaJY81q+PL+J4Ngh0fxdVtF9apyGcOlMT7Q0Vz
# AgMBAAGjggFjMIIBXzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTHaTwu5r3jWUf/
# GRLB2TToQc/jjzAfBgNVHSMEGDAWgBS+VAIvv0Bsc0POrAklTp5DRBru4DAOBgNV
# HQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwMwYDVR0fBCwwKjAo
# oCagJIYiaHR0cDovL2NybC5jZXJ0dW0ucGwvY3RzY2EyMDIxLmNybDBvBggrBgEF
# BQcBAQRjMGEwKAYIKwYBBQUHMAGGHGh0dHA6Ly9zdWJjYS5vY3NwLWNlcnR1bS5j
# b20wNQYIKwYBBQUHMAKGKWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9jdHNj
# YTIwMjEuY2VyMEEGA1UdIAQ6MDgwNgYLKoRoAYb2dwIFAQswJzAlBggrBgEFBQcC
# ARYZaHR0cHM6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkqhkiG9w0BAQwFAAOCAgEA
# eN3usTpD5vfZazi9Ml4LQdwYOLuZ9BSdton2cUU5CmLM9f5gike4rz1M+Q50MXuU
# 4SZNnNVCnDSTCkhkO4HyVIzQbD0qWg69ciwaMX8qBM3FgzlpWJA0y2giIXpb3Kya
# 5sMcXuUTFJOg93Wv43TNgZeUTW4Rfij3zwr9nuTCAT8YLrj1LU4RnkgZIaaKu1yu
# 4tf/GGMgMDlL9xV/PRZ78SUdqYez5R9bf8jFOKC++rgkJt1keD0OyORb5SAYYBW2
# TEHuqKeZYlqa93CmC6MDA5PXKb+CI9NbkLz8yeQvXxmBVDfyyoqoV2pRL5khV5cp
# 9Xnwdpa1XYuKnVjSW4vsyzBvznqPPvNcg2Tv0fhd9tY6vJ/sC1YGOu6zbyOYdYre
# Bc2GPZK1Vw4jjwNzoIV9cMyj9z8T9pvbXuRNiGKG3asJZ4ZLlMdDdtlXH6VQ8toN
# 7eRVeNi/ExhApa7ThBfr69REVJ4vdZWtRI7qcSdm7tfYRhyLkxSaZR0QSIBVk7/T
# fIuU1ZQ0Zfvb/3j29T7lk32v0QZ2ntfdbuYsvVPHiAuYeesH3s7571FgrrfvQwLn
# ayK5+7XWnefw4bmzbMnDYnoukP4ctvIKB9Eh31DlQqCyPQDVC6gG63wUjph1ofex
# HWmicS/oaw1itPIG1JHvtyxRYtQLJVuiwXf5p7T5Kh8wgga5MIIEoaADAgECAhEA
# maOACiZVO2Wr3G6EprPqOTANBgkqhkiG9w0BAQwFADCBgDELMAkGA1UEBhMCUEwx
# IjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAlBgNVBAsTHkNl
# cnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMbQ2VydHVtIFRy
# dXN0ZWQgTmV0d29yayBDQSAyMB4XDTIxMDUxOTA1MzIxOFoXDTM2MDUxODA1MzIx
# OFowVjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMg
# Uy5BLjEkMCIGA1UEAxMbQ2VydHVtIENvZGUgU2lnbmluZyAyMDIxIENBMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnSPPBDAjO8FGLOczcz5jXXp1ur5c
# Tbq96y34vuTmflN4mSAfgLKTvggv24/rWiVGzGxT9YEASVMw1Aj8ewTS4IndU8s7
# VS5+djSoMcbvIKck6+hI1shsylP4JyLvmxwLHtSworV9wmjhNd627h27a8RdrT1P
# H9ud0IF+njvMk2xqbNTIPsnWtw3E7DmDoUmDQiYi/ucJ42fcHqBkbbxYDB7SYOou
# u9Tj1yHIohzuC8KNqfcYf7Z4/iZgkBJ+UFNDcc6zokZ2uJIxWgPWXMEmhu1gMXgv
# 8aGUsRdaCtVD2bSlbfsq7BiqljjaCun+RJgTgFRCtsuAEw0pG9+FA+yQN9n/kZtM
# LK+Wo837Q4QOZgYqVWQ4x6cM7/G0yswg1ElLlJj6NYKLw9EcBXE7TF3HybZtYvj9
# lDV2nT8mFSkcSkAExzd4prHwYjUXTeZIlVXqj+eaYqoMTpMrfh5MCAOIG5knN4Q/
# JHuurfTI5XDYO962WZayx7ACFf5ydJpoEowSP07YaBiQ8nXpDkNrUA9g7qf/rCkK
# bWpQ5boufUnq1UiYPIAHlezf4muJqxqIns/kqld6JVX8cixbd6PzkDpwZo4SlADa
# Ci2JSplKShBSND36E/ENVv8urPS0yOnpG4tIoBGxVCARPCg1BnyMJ4rBJAcOSnAW
# d18Jx5n858JSqPECAwEAAaOCAVUwggFRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
# BBYEFN10XUwA23ufoHTKsW73PMAywHDNMB8GA1UdIwQYMBaAFLahVDkCw6A/joq8
# +tT4HKbROg79MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDAzAw
# BgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vY3JsLmNlcnR1bS5wbC9jdG5jYTIuY3Js
# MGwGCCsGAQUFBwEBBGAwXjAoBggrBgEFBQcwAYYcaHR0cDovL3N1YmNhLm9jc3At
# Y2VydHVtLmNvbTAyBggrBgEFBQcwAoYmaHR0cDovL3JlcG9zaXRvcnkuY2VydHVt
# LnBsL2N0bmNhMi5jZXIwOQYDVR0gBDIwMDAuBgRVHSAAMCYwJAYIKwYBBQUHAgEW
# GGh0dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkqhkiG9w0BAQwFAAOCAgEAdYhY
# D+WPUCiaU58Q7EP89DttyZqGYn2XRDhJkL6P+/T0IPZyxfxiXumYlARMgwRzLRUS
# tJl490L94C9LGF3vjzzH8Jq3iR74BRlkO18J3zIdmCKQa5LyZ48IfICJTZVJeChD
# UyuQy6rGDxLUUAsO0eqeLNhLVsgw6/zOfImNlARKn1FP7o0fTbj8ipNGxHBIutiR
# sWrhWM2f8pXdd3x2mbJCKKtl2s42g9KUJHEIiLni9ByoqIUul4GblLQigO0ugh7b
# WRLDm0CdY9rNLqyA3ahe8WlxVWkxyrQLjH8ItI17RdySaYayX3PhRSC4Am1/7mAT
# wZWwSD+B7eMcZNhpn8zJ+6MTyE6YoEBSRVrs0zFFIHUR08Wk0ikSf+lIe5Iv6RY3
# /bFAEloMU+vUBfSouCReZwSLo8WdrDlPXtR0gicDnytO7eZ5827NS2x7gCBibESY
# kOh1/w1tVxTpV2Na3PR7nxYVlPu1JPoRZCbH86gc96UTvuWiOruWmyOEMLOGGniR
# +x+zPF/2DaGgK2W1eEJfo2qyrBNPvF7wuAyQfiFXLwvWHamoYtPZo0LHuH8X3n9C
# +xN4YaNjt2ywzOr+tKyEVAotnyU9vyEVOaIYMk3IeBrmFnn0gbKeTTyYeEEUz/Qw
# t4HOUBCrW602NCmvO1nm+/80nLy5r0AZvCQxaQ4wgga5MIIEoaADAgECAhEA5/9p
# xzs1zkuRJth0fGilhzANBgkqhkiG9w0BAQwFADCBgDELMAkGA1UEBhMCUEwxIjAg
# BgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAlBgNVBAsTHkNlcnR1
# bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMbQ2VydHVtIFRydXN0
# ZWQgTmV0d29yayBDQSAyMB4XDTIxMDUxOTA1MzIwN1oXDTM2MDUxODA1MzIwN1ow
# VjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5B
# LjEkMCIGA1UEAxMbQ2VydHVtIFRpbWVzdGFtcGluZyAyMDIxIENBMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6RIfBDXtuV16xaaVQb6KZX9Od9FtJXXT
# Zo7b+GEof3+3g0ChWiKnO7R4+6MfrvLyLCWZa6GpFHjEt4t0/GiUQvnkLOBRdBqr
# 5DOvlmTvJJs2X8ZmWgWJjC7PBZLYBWAs8sJl3kNXxBMX5XntjqWx1ZOuuXl0R4x+
# zGGSMzZ45dpvB8vLpQfZkfMC/1tL9KYyjU+htLH68dZJPtzhqLBVG+8ljZ1ZFilO
# KksS79epCeqFSeAUm2eMTGpOiS3gfLM6yvb8Bg6bxg5yglDGC9zbr4sB9ceIGRtC
# QF1N8dqTgM/dSViiUgJkcv5dLNJeWxGCqJYPgzKlYZTgDXfGIeZpEFmjBLwURP5A
# BsyKoFocMzdjrCiFbTvJn+bD1kq78qZUgAQGGtd6zGJ88H4NPJ5Y2R4IargiWAmv
# 8RyvWnHr/VA+2PrrK9eXe5q7M88YRdSTq9TKbqdnITUgZcjjm4ZUjteq8K331a4P
# 0s2in0p3UubMEYa/G5w6jSWPUzchGLwWKYBfeSu6dIOC4LkeAPvmdZxSB1lWOb9H
# zVWZoM8Q/blaP4LWt6JxjkI9yQsYGMdCqwl7uMnPUIlcExS1mzXRxUowQref/EPa
# S7kYVaHHQrp4XB7nTEtQhkP0Z9Puz/n8zIFnUSnxDof4Yy650PAXSYmK2TcbyDoT
# Nmmt8xAxzcMCAwEAAaOCAVUwggFRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FL5UAi+/QGxzQ86sCSVOnkNEGu7gMB8GA1UdIwQYMBaAFLahVDkCw6A/joq8+tT4
# HKbROg79MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDCDAwBgNV
# HR8EKTAnMCWgI6Ahhh9odHRwOi8vY3JsLmNlcnR1bS5wbC9jdG5jYTIuY3JsMGwG
# CCsGAQUFBwEBBGAwXjAoBggrBgEFBQcwAYYcaHR0cDovL3N1YmNhLm9jc3AtY2Vy
# dHVtLmNvbTAyBggrBgEFBQcwAoYmaHR0cDovL3JlcG9zaXRvcnkuY2VydHVtLnBs
# L2N0bmNhMi5jZXIwOQYDVR0gBDIwMDAuBgRVHSAAMCYwJAYIKwYBBQUHAgEWGGh0
# dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkqhkiG9w0BAQwFAAOCAgEAuJNZd8lM
# Ff2UBwigp3qgLPBBk58BFCS3Q6aJDf3TISoytK0eal/JyCB88aUEd0wMNiEcNVMb
# K9j5Yht2whaknUE1G32k6uld7wcxHmw67vUBY6pSp8QhdodY4SzRRaZWzyYlviUp
# yU4dXyhKhHSncYJfa1U75cXxCe3sTp9uTBm3f8Bj8LkpjMUSVTtMJ6oEu5JqCYzR
# fc6nnoRUgwz/GVZFoOBGdrSEtDN7mZgcka/tS5MI47fALVvN5lZ2U8k7Dm/hTX8C
# WOw0uBZloZEW4HB0Xra3qE4qzzq/6M8gyoU/DE0k3+i7bYOrOk/7tPJg1sOhytOG
# UQ30PbG++0FfJioDuOFhj99b151SqFlSaRQYz74y/P2XJP+cF19oqozmi0rRTkfy
# EJIvhIZ+M5XIFZttmVQgTxfpfJwMFFEoQrSrklOxpmSygppsUDJEoliC05vBLVQ+
# gMZyYaKvBJ4YxBMlKH5ZHkRdloRYlUDplk8GUa+OCMVhpDSQurU6K1ua5dmZftnv
# SSz2H96UrQDzA6DyiI1V3ejVtvn2azVAXg6NnjmuRZ+wa7Pxy0H3+V4K4rOTHlG3
# VYA6xfLsTunCz72T6Ot4+tkrDYOeaU1pPX1CBfYj6EW2+ELq46GP8KCNUQDirWLU
# 4nOmgCat7vN0SD6RlwUiSsMeCiQDmZwgwrUwggbYMIIEwKADAgECAhAucYDTeFlE
# bHhAwyUgI2H5MA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQK
# ExhBc3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2Rl
# IFNpZ25pbmcgMjAyMSBDQTAeFw0yNDEyMzAxMjU4MjdaFw0yNTEyMzAxMjU4MjZa
# MH4xCzAJBgNVBAYTAkJFMQ4wDAYDVQQIDAVOYW11cjENMAsGA1UEBwwETWV1eDEe
# MBwGA1UECgwVT3BlbiBTb3VyY2UgRGV2ZWxvcGVyMTAwLgYDVQQDDCdPcGVuIFNv
# dXJjZSBEZXZlbG9wZXIsIEFsZXhhbmRyZSBKQVJET04wggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCrY3bRJ4SDZazxjqRaSopnV7YY9uM0H1DPVbnBrY2w
# 4aDe+JJwn3KnTlnXMITTgispaYp9kWfw1bMbVDbMVfAzoQ7BcycDygrZ1kayAUfd
# oVox82jZnPG10XApxp71m+QvTg+JWtRFy0j0qq/tD8h1UlewmLrmRYPwq3ybwGFZ
# CkrYHqbtarKLeukeUhefdezPs1PAlZ6CGfHBkeL3J1rPlhAnG/HTOoRO7I1n8gWI
# tgCsvefHW0wvAS/tujZy09YhN3MPRWtTjp4RIQIfgVrfUYDvpFLAeAFuqY1BP7te
# GApaDxqErbF7SiKkP5sOngnCRbs7ua3/ON45WaOXPeEJ40laZuptN6Y1bZbKDljj
# OJFCGBp2GgHHKmZ17fmu2oJGhDl5CHd52/FWjEBqtPusHdhjBLPtf+d32PSD+uaj
# d0eOOcLXhx1703baI0CBJQMZKXggiPoXIoY4AbKXFjq5LkZYxxlkrLs9fSROQoi2
# nu+6FHGFJokZS4MpxhpkgnXm8fpokCjfWW7VqiKOQVmWOJgtC8Y3G3RL7decdHk1
# fqGdADL2mkIklHn2aOK4RkofrbUKMQCJEkSDRhI0lS8YORBY6L+43+HGE6Y71ui8
# S/uKV7Dg0ZUllfdmgSICmSXx4FCzMcA9cSVqlZLNQuQat6AW2LgNCKG3DyXYR7TQ
# 8QIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKgMKAuhixo
# dHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNybDBzBggr
# BgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEub2NzcC1j
# ZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5jZXJ0dW0u
# cGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu9zzAMsBw
# zTAdBgNVHQ4EFgQUCuS/JIkb5Bf9AiWFEOPykx+lClkwSwYDVR0gBEQwQjAIBgZn
# gQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6Ly93d3cu
# Y2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMC
# B4AwDQYJKoZIhvcNAQELBQADggIBAEn4iH018xKD5F9ud4QCZp7f1ArO2BWgF90B
# R8UH/ULdFsNe46LsNfFcnAv06bVCX3OPh5JREtuLt3iStuekShV1f6ZLDxrtO8lH
# 9wpxq19wdeBSnc3+6D+AraqFeaGxKy4Eq7HlGMUR0lvr1evk8gq1LUy+GZPt0J03
# hz6PISk0zLrTFXSVde0b5x74ooq5A4w0u42SV/8JK38HfeXiCdiDaEDTPSZD4Fcy
# 4e8SoZW5hPLen6VzExj/anz207RTjSQd7T6VhBctB3cCe06S05Ht2G1dL3h1cgSn
# kXcY/ieIoDkpqBqRM15yic498zJKRzZ9ATBXHCPsGc/3Anesw8kOLrkrVmJBt+Zl
# Esr6zh6ajHAC8koLAfNE3qWhKtliqP0T6EyrVoJZeLHQ+/Yy0WyYdGpuMXotTXvw
# cfGsYBP+82ZFlvK3NqDUQssIhUzzNCdIx9G7ggzH/oKO2p/11SKNKzM0qqPLYEGt
# verq90llVHIzJ8UeWc6xZunbVUVA37w5r1lB1afKAlibHax1xOjpTDAuchz7A8vq
# SR4wnoJNLRgBmM256a3fR/zlwcVqrG/D0mBlp+oyNq56Qmz2X8Ojgx9oVmw7f0W9
# pL5HvWQuEpH8Q2IxpGy2irsVfdqoFvodm8jNmWXLHsBz2vstTVtZwXDlMQJMkpWR
# rwimvLcYMYIHIjCCBx4CAQEwajBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMYQXNz
# ZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBTaWdu
# aW5nIDIwMjEgQ0ECEC5xgNN4WURseEDDJSAjYfkwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQg893x1abdhyHGdE/uOskWZZpwm19zVBy6TG8k9vKXbT4wDQYJKoZIhvcNAQEB
# BQAEggIAjCXxJoV1xuMTHUVpvzv/e+PQHgR2rT2ET2oCD2DspzmiIZ+hNKlqi6ab
# PyKzOvXbwvj0ok/eZIH4q9125joZudqZsXUlUhAY6QIz44uvR5Q6kLN1IcRh2SbN
# 7Z2gWvaperykJ1MQt/kkC2/r9KrABpPiMonAXTSXG2Lv8DrYnROj/dFJuOlA70Uk
# bWzRqbZ4ezZk1ROMgTdCWh4ACTLn5vlv0tRS7sKMR08OnOjd/RAodgHHon+16dIu
# 82jpLcpxwE79qSnYjjX7fotSrLBPvY9RzGU6OIaKutxIp6G5UWRR7ncad300YRxP
# 7J16yPEEMfiPjg3eZtirKyLkjx+RNTCaYKWU+oCZnZXD5RZEPF44k7/t6dq+RwVD
# lTe4SUFn5No8sFpNKxycq6wXFNJDvB4efSL/h8ROagxTVskORjWUbkMTg8LB3IZz
# vRUjsIB50WGszh0/R3GlGm9GZUiXDaUc8liItfacMtIGMJsjkxuxBKUNA+HTTD/S
# hhnLxUfGniyTfD3EBN+pdnG8/i5I6YPXGXjh3rHUy49JhJcr29734u9189ifLTTS
# x4UAwacU/pYkY66ISaYu3ZdTxsJWCicbAuaKwQb4zHDKH8zsq8adfqCPYdcf+e2q
# da/hAKio4Xi54zjnb0qAwtxz/jgpN+bHQbUYbkyT09S2QKMEcYChggQCMIID/gYJ
# KoZIhvcNAQkGMYID7zCCA+sCAQEwajBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gVGltZXN0
# YW1waW5nIDIwMjEgQ0ECEAnFzPi7Zn1xN6rBWYAGyzEwDQYJYIZIAWUDBAICBQCg
# ggFWMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjUwMTAyMTQ0MzAxWjA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDqlUux0EC0MUBI
# 2GWfj2FdiHQszOBnkuBWAk1LADrTHDA/BgkqhkiG9w0BCQQxMgQwx8BBIHGrxGkc
# MxDWy0cmJaxj7eXMWH6BEiq6SkW9Uc0ySbSn4HbLtcFGj6nTWSQ4MIGfBgsqhkiG
# 9w0BCRACDDGBjzCBjDCBiTCBhgQUD0+4VR7/2Pbef2cmtDwT0Gql53cwbjBapFgw
# VjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5B
# LjEkMCIGA1UEAxMbQ2VydHVtIFRpbWVzdGFtcGluZyAyMDIxIENBAhAJxcz4u2Z9
# cTeqwVmABssxMA0GCSqGSIb3DQEBAQUABIICABX3K+BYXAmFGlMC+Jrb1Qnde7ph
# Y7ec5Ok5gvvdb0tTFETWHGTWXuAF0Ogw/ukGGROVnK/pJOWrAmESeeW1uY/eFzHG
# 0Ddo/WDWuTZR6gBeDtyszKB+yLHW+e0XhojoCeNF7sADaehjHcBwORP76rZ5OQ44
# 9mveQVz0pPUgOe36qVffQcLlrL7MBTAxA58+gmovu/cIMXgrk/iIiulTpdExFQDZ
# MFwoC+7OfOGaoIgcrSiDpHOmA8NEw6BA7Tr6QeFqQPPOvlNn9EZO04LsCYt8GMMd
# hBJGszat2FBG0KNYaXRDHbdZIPIbMNHZ2JjioOTAq83iD4it2zNiBh7t661JfIdQ
# 8KgXwrsF8gD7rWJ+sVQ8fB1iPWfwvHeuDk+ooBxhckfvGCXskFRn7b13BGOy1EY6
# nrnqsSBoee0NdHJdX/ZYh8uSjNbdNotwKZmrdjLvpYhQMvk0swe1iiy0EDS0M0dJ
# g4OQ/hTQ3BELl6uEoq4OZHIn0sUFS79yQTM2p4Q52v3sSx7rxq/k4rgVgjIdOpQl
# lCU3d2eT7Zn9fWJP7kAh49PFHvbXZlXiRQmdPpDRpT317jxkNaGrUeUAylwm24LI
# 9hnkv7tRctkfPDsa1MEYx64Z0HvmOPbANLeQ9a//0HcCSZreWRpwyDUQhCNxtR/M
# UaI7wEuDz7KqxPnT
# SIG # End signature block
