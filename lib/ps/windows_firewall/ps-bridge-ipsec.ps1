###############################################################################################
#                                                                                             #
#   Name            PS-Bridge-IPSec                                                           #
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
    [String] $Description,
    $Enabled,
    [String] $Protocol,
    [String] $Mode,
    $Profile,
    [String] $LocalAddress,
    [String] $RemoteAddress,
    [String] $LocalPort,
    [String] $RemotePort,
    $InterfaceType,
    $Phase1AuthSet,
    $Phase2AuthSet,
    $InboundSecurity,
    $OutboundSecurity
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

function show {
    $rules = New-Object System.Collections.ArrayList

    # Firewall IPsecrules query (InstanceID is the unique key)
    $firewallRules = Get-NetIPsecRule | Select-Object InstanceID, Name, DisplayName, Description, Enabled, Profile, DisplayGroup, Mode, InboundSecurity, OutboundSecurity, Phase1AuthSet, Phase2AuthSet
    # Run Firewall rules filter queries only if Firewall IPSec Rules exists (Until both scripts are merged in one single PowerShell script to manage everything)
    if ($firewallRules) {
        # Querying Firewall rules filter in one query (Parsing for each rule is cpu/time consuming)
        $af_rules = Get-NetFirewallAddressFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|ConSecRule|*'} | Select-Object InstanceID, LocalAddress, RemoteAddress
        $pf_rules = Get-NetFirewallPortFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|ConSecRule|*'} | Select-Object InstanceID, LocalPort, RemotePort, Protocol
        $if_rules = Get-NetFirewallInterfaceTypeFilter | Where-Object {$_.CreationClassName -like 'MSFT|FW|ConSecRule|*'} | Select-Object InstanceID, InterfaceType
    }

    # Parse all firewall rules (Using foreach to improve performance)
    ForEach ($firewallRule in $firewallRules) {
        ## Parsing using foreach to improve performance
        $InstanceID=$firewallRule.InstanceID
        ForEach ($af_rule in $af_rules) {if ($af_rule.InstanceID -eq $InstanceID) {$af=$af_rule}}
        ForEach ($pf_rule in $pf_rules) {if ($pf_rule.InstanceID -eq $InstanceID) {$pf=$pf_rule}}
        ForEach ($if_rule in $if_rules) {if ($if_rule.InstanceID -eq $InstanceID) {$if=$if_rule}}
        
        # TO BE IMPLEMENTED
        #$Phase1AuthSet = (Get-NetIPsecPhase1AuthSet -AssociatedNetIPsecRule $_)[0]
        #$Phase2AuthSet = (Get-NetIPsecPhase2AuthSet -AssociatedNetIPsecRule $_)[0]

        $rules.Add(@{
                Name                = $firewallRule.Name
                DisplayName         = $firewallRule.DisplayName
                Description         = $firewallRule.Description
                Enabled             = $firewallRule.Enabled.toString()
                Profile             = $firewallRule.Profile.toString()
                DisplayGroup        = $firewallRule.DisplayGroup
                Mode                = $firewallRule.Mode.toString()
                # Address Filter (Newer powershell versions return a hash) - Return are sorted to be displayed properly in resources output
                LocalAddress        = if ($af.LocalAddress -is [object]) { ($af.LocalAddress | ForEach-Object {Convert-IpAddressToMaskLength $_} | Sort-Object) } else { Convert-IpAddressToMaskLength $af.LocalAddress.toString() }
                RemoteAddress       = if ($af.RemoteAddress -is [object]) { ($af.RemoteAddress | ForEach-Object {Convert-IpAddressToMaskLength $_} | Sort-Object) } else { Convert-IpAddressToMaskLength $af.RemoteAddress.toString() }
                # Port Filter (Newer powershell versions return a hash) - Return are sorted to be displayed properly in resources output
                LocalPort           = if ($pf.LocalPort -is [object]) { $pf.LocalPort | Sort-Object } else { $pf.LocalPort.toString() }
                RemotePort          = if ($pf.RemotePort -is [object]) { $pf.RemotePort | Sort-Object } else { $pf.RemotePort.toString() }
                Protocol            = $pf.Protocol
                # Interface Filter
                InterfaceType       = $if.InterfaceType.toString()
                InboundSecurity     = $firewallRule.InboundSecurity.toString()
                OutboundSecurity    = $firewallRule.OutboundSecurity.toString()
                Phase1AuthSet       = if ($null -ne $firewallRule.Phase1AuthSet) { $firewallRule.Phase1AuthSet } else { 'None' }
                Phase2AuthSet       = if ($null -ne $firewallRule.Phase2AuthSet) { $firewallRule.Phase2AuthSet } else { 'None' }
            }) > $null
    }

    convertto-json $rules

}

function create {
    write-host "Creating $Name"

    $params = @{
        Name        = $Name;
        Enabled     = $Enabled;
        DisplayName = $DisplayName;
        Description = $Description;
    }

    #
    # general optional params
    #

    if ($Profile) {
        $params.Add("Profile", $Profile)
    }

    #
    # port filter
    #
    if ($Protocol) {
        $params.Add("Protocol", $Protocol)
    }
    if ($Mode) {
        $params.Add("Mode", $Mode)
    }

    # `$LocalPort` and `$RemotePort` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split
    if ($LocalPort) {
        $params.Add("LocalPort", ($LocalPort -split ','))
    }
    if ($RemotePort) {
        $params.Add("RemotePort", ($RemotePort -split ','))
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
    if ($InboundSecurity) {
        $params.Add("InboundSecurity", $InboundSecurity)
    }
    if ($OutboundSecurity) {
        $params.Add("OutboundSecurity", $OutboundSecurity)
    }
    #PhaseAuthSet is case sensitive
    if ($Phase1AuthSet -eq 'Computerkerberos') {
        $params.Add("Phase1AuthSet", 'ComputerKerberos')
    }
    elseif ($Phase1AuthSet) {
        $params.Add("Phase1AuthSet", $Phase1AuthSet)
    }
    if ($Phase2AuthSet -eq 'Userkerberos') {
        $params.Add("Phase2AuthSet", 'UserKerberos')
    }
    elseif ($Phase2AuthSet) {
        $params.Add("Phase2AuthSet", $Phase2AuthSet)
    }

    #Create PhaseAuthSet if doesn't exist (Exist by default on GUI but not on CORE)
    if ($Phase1AuthSet -eq 'Computerkerberos') {
        if (!(Get-NetIPsecPhase1AuthSet -Name 'ComputerKerberos' -erroraction 'silentlycontinue')) {
            $mkerbauthprop = New-NetIPsecAuthProposal -Machine -Kerberos
            New-NetIPsecPhase1AuthSet -Name 'ComputerKerberos' -DisplayName 'ComputerKerberos' -Proposal $mkerbauthprop
        }
    }
    elseif ($Phase1AuthSet -eq 'Anonymous') {
        if (!(Get-NetIPsecPhase1AuthSet -Name 'Anonymous' -erroraction 'silentlycontinue')) {
            $anonyauthprop = New-NetIPsecAuthProposal -Anonymous
            New-NetIPsecPhase1AuthSet -Name 'Anonymous' -DisplayName 'Anonymous' -Proposal $anonyauthprop
        }
    }
    if ($Phase2AuthSet -eq 'Userkerberos') {
        #Create Phase1AuthSet if doesn't exist (Exist by default on GUI but not on CORE)
        if (!(Get-NetIPsecPhase2AuthSet -Name 'Userkerberos' -erroraction 'silentlycontinue')) {
            $ukerbauthprop = New-NetIPsecAuthProposal -User -Kerberos
            New-NetIPsecPhase2AuthSet -Name 'Userkerberos' -DisplayName 'Userkerberos' -Proposal $ukerbauthprop
        }
    }

    New-NetIPSecRule @params -ErrorAction Stop
}

function update {
    write-host "Updating $Name"

    # rules containing square brackets need to be escaped or nothing will match
    $Name = $name.replace(']', '`]').replace('[', '`[')

    $params = @{
        Enabled        = $Enabled;
        NewDisplayName = $DisplayName;
        Description    = $Description;
    }

    #
    # general optional params
    #

    if ($Profile) {
        $params.Add("Profile", $Profile)
    }

    #
    # port filter
    #
    if ($Protocol) {
        $params.Add("Protocol", $Protocol)
    }
    if ($Mode) {
        $params.Add("Mode", $Mode)
    }

    # `$LocalPort` and `$RemotePort` will always be strings since we were
    # invoked with `powershell -File`, rather then refactor the loader to use
    # `-Command`, just do a simple string split
    if ($LocalPort) {
        $params.Add("LocalPort", ($LocalPort -split ','))
    }
    if ($RemotePort) {
        $params.Add("RemotePort", ($RemotePort -split ','))
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
    if ($InboundSecurity) {
        $params.Add("InboundSecurity", $InboundSecurity)
    }
    if ($OutboundSecurity) {
        $params.Add("OutboundSecurity", $OutboundSecurity)
    }
    #PhaseAuthSet is case sensitive
    if ($Phase1AuthSet -eq 'Computerkerberos') {
        $params.Add("Phase1AuthSet", 'ComputerKerberos')
    }
    elseif ($Phase1AuthSet) {
        $params.Add("Phase1AuthSet", $Phase1AuthSet)
    }
    if ($Phase2AuthSet -eq 'Userkerberos') {
        $params.Add("Phase2AuthSet", 'UserKerberos')
    }
    elseif ($Phase2AuthSet) {
        $params.Add("Phase2AuthSet", $Phase2AuthSet)
    }

    #Create PhaseAuthSet if doesn't exist (Exist by default on GUI but not on CORE)
    if ($Phase1AuthSet -eq 'Computerkerberos') {
        if (!(Get-NetIPsecPhase1AuthSet -Name 'ComputerKerberos' -erroraction 'silentlycontinue')) {
            $mkerbauthprop = New-NetIPsecAuthProposal -Machine -Kerberos
            New-NetIPsecPhase1AuthSet -Name 'ComputerKerberos' -DisplayName 'ComputerKerberos' -Proposal $mkerbauthprop
        }
    }
    elseif ($Phase1AuthSet -eq 'Anonymous') {
        if (!(Get-NetIPsecPhase1AuthSet -Name 'Anonymous' -erroraction 'silentlycontinue')) {
            $anonyauthprop = New-NetIPsecAuthProposal -Anonymous
            New-NetIPsecPhase1AuthSet -Name 'Anonymous' -DisplayName 'Anonymous' -Proposal $anonyauthprop
        }
    }
    if ($Phase2AuthSet -eq 'Userkerberos') {
        #Create Phase1AuthSet if doesn't exist (Exist by default on GUI but not on CORE)
        if (!(Get-NetIPsecPhase2AuthSet -Name 'Userkerberos' -erroraction 'silentlycontinue')) {
            $ukerbauthprop = New-NetIPsecAuthProposal -User -Kerberos
            New-NetIPsecPhase2AuthSet -Name 'Userkerberos' -DisplayName 'Userkerberos' -Proposal $ukerbauthprop
        }
    }

    if (Get-NetIPSecRule -Name $name -erroraction SilentlyContinue) {
        Set-NetIPSecRule -Name $name @params -ErrorAction Stop
    }
    else {
        throw "We were told to update firewall rule '$($name)' but it does not exist"
    }
}

function delete {
    write-host "Deleting $Name"

    # rules containing square brackets need to be escaped or nothing will match
    $Name = $name.replace(']', '`]').replace('[', '`[')

    if (Get-NetIPSecRule -Name $name -ErrorAction SilentlyContinue) {
        Remove-NetIPSecRule -Name $Name -ErrorAction Stop
    }
    else {
        throw "We were told to delete firewall rule '$($name)' but it does not exist"
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD6V6Ka4PYd9r9I
# ZoeMzWhwD1PtVw+L/uajeyC1o56W06CCILwwggXJMIIEsaADAgECAhAbtY8lKt8j
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
# IgQgnE9TCcM7Y3EVbQHXB5CNtLPUm4319mFqEUxilLJ6SRUwDQYJKoZIhvcNAQEB
# BQAEggIABCQzemXatAh13OEc8OUsZu86hG6M+Sp2qSd0/X3H9F2cIHmq4z1ZMS9M
# wTbhXTbvt+IPps49oIeWDRrLCwIlwL/OivQXX+X64mxed4/+M/rF/wPB1iZJ0+Bm
# suDdgP7nAiWd01necPtZvShFtdzHv1WXDc2yp0htlF+HxX9+lx9BZVhQK0kaK+HI
# tpCvBpUXZLb03EQGA+mBw+ucL1Qe/aOmiR++N3ZFdGhj7I0HttIFnoJWr2RLS43G
# Z4Y4/6HkD5/BMrBxTrcbvqmqREEsFZibtrFmV67xI2CYFrqV4bcRlPy4TkD0JIWR
# B9MUkEieDwgwWTBOxEpTsU+D9yd5vlODkBi5dXcuhL15b0iMwJCx8da2naBlMQIJ
# KrTOM9o+W2N4xMIqzsysGOv6znt4zc5l2ZdbnZmCqKFv9DjmetxLUYq3hwqXwuZ0
# lSPXDU+MrB2x19gFgpzKHFpgb4BieJvwT98/ibzP9V5aKg2fJe5F+GuMIN/pD9T7
# Q3yOggK0fnvzx0vN9uU6STW7Kh0juKM7CbbIGtAovw7aakifz/aLXCStnyVvtVmQ
# 4oCCLLkRE93t53fWLCwBillIZoych8taH5tueehB0ve0usYQ20iEErREEm6PHXn+
# Xp/Xno9Mbw9XYlQp3Orx7hafdnKaK1+7EafFh/jmsFi7JpSTqMihggQCMIID/gYJ
# KoZIhvcNAQkGMYID7zCCA+sCAQEwajBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gVGltZXN0
# YW1waW5nIDIwMjEgQ0ECEAnFzPi7Zn1xN6rBWYAGyzEwDQYJYIZIAWUDBAICBQCg
# ggFWMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjUwMTAyMTQ0MjUwWjA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDqlUux0EC0MUBI
# 2GWfj2FdiHQszOBnkuBWAk1LADrTHDA/BgkqhkiG9w0BCQQxMgQwHAbyLDkfuc5B
# vjv4jPciMfyMuIufwNS/OaQ2F/Z+e+iOM5FWXqWc6g6drdvqtaogMIGfBgsqhkiG
# 9w0BCRACDDGBjzCBjDCBiTCBhgQUD0+4VR7/2Pbef2cmtDwT0Gql53cwbjBapFgw
# VjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5B
# LjEkMCIGA1UEAxMbQ2VydHVtIFRpbWVzdGFtcGluZyAyMDIxIENBAhAJxcz4u2Z9
# cTeqwVmABssxMA0GCSqGSIb3DQEBAQUABIICAKSEJloQqCY/h/T/QZsSWrS329w3
# Qy4WItQaA/zDqiDKgT9uQYARrUJJZYdAPLCoDyFSLdZnDSwSs9CV6rYZqq69KS6r
# fe91l/vfQMWLKPZAX4jMwRDkP+PkHfowCxvwcsDq/u2Ij1JJozU7LJCK+TEL5o5o
# xXUfKPih3UNSOYDNnI51twoPax3Dsh6jWLhfD9sk2pZK2jk6qQHEu02aaLDU77g+
# O/YxzzFwJn4C+kZHfPB9yB07m6Q+exF8bpvo7tT7t0trGnzZ2bQBUAqPKaOf3jDT
# /lu0A3Km4ewWRdknSzEaSmxak8RsEAXcmA/bBkB8wpwVZRKphov1mhIIyuk/YqF8
# GUZdq/tqQWIzLQ2D/+/MqR0Cctl2ybNDFG0KyonJPuJDf3cG5mgZ1OGa6EdA9j8b
# LMsq3iNQr/55N6HOcbPSY7TD86O0vBlyoK4rA4ybNMqqbOOtgfHrqpYgLOFMDiOT
# tT3A+Vvm25qrgLfQ7P14D/f8kkcMnYxjYzdxYxqjSpSYX2aSlPsdXfTL6tJaPPmV
# 9B0+USEJy2raIyWQXgzOlXTEYL2UQQsjl3NOvhySUI7RdpvVp50A3NN6kM0u5gRA
# RkUCgsFomHAPlqlIZKzEtInXYk+KbzLc6TGa0ziK2w34khiHj/EHq8bJbPTC83jS
# mZuVJxaEqXT/OBJK
# SIG # End signature block
