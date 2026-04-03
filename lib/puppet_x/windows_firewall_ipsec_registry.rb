require 'puppet_x'
require 'puppet/util'

# Manages Windows Firewall IPSec connection security rules by writing directly
# to the registry.
#
# Rules are stored as REG_SZ values under:
#   HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\ConnectionSecurityRules
#
# Each value name is the rule's Name (namevar) and the data is a pipe-delimited
# string in the Windows Firewall v2.31 format, e.g.:
#   v2.31|Action=ConSecRule|Active=TRUE|Dir=Both|Protocol=6|LPort=443|LA4=Any|RA4=Any|
#     Mode=Transport|InboundSec=Require|OutboundSec=Require|Auth1=ComputerKerb|
#     Auth2=UserKerb|Name=My IPSec Rule|Desc=|Profile=Any|IF=Any|
#
# Windows Firewall monitors this registry key and exposes all values through the
# NetSecurity PowerShell module, so rule discovery continues to work via PowerShell.
module PuppetX
  module WindowsFirewallIPSecRegistry
    CONNECTION_SECURITY_RULES_PATH = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\ConnectionSecurityRules'.freeze

    # Maps Puppet protocol symbols/strings to IANA protocol numbers.
    # IPSec rules do not support 'any' protocol — protocol is always required.
    PROTOCOL_TO_REG = {
      'icmpv4' => '1',
      'tcp'    => '6',
      'udp'    => '17',
      'icmpv6' => '58',
    }.freeze

    # Maps Puppet profile symbols to registry strings.
    PROFILE_TO_REG = {
      'domain'  => 'Domain',
      'private' => 'Private',
      'public'  => 'Public',
      'any'     => 'Any',
    }.freeze

    # Maps Puppet interface_type symbols to registry strings.
    INTERFACE_TYPE_TO_REG = {
      'any'           => 'Any',
      'wired'         => 'Lan',
      'wireless'      => 'Wireless',
      'remote_access' => 'Ras',
    }.freeze

    # Maps Puppet mode to registry strings.
    MODE_TO_REG = {
      'none'      => 'NoEncapsulation',
      'transport' => 'Transport',
      'tunnel'    => 'Tunnel',
    }.freeze

    # Maps Puppet inbound_security / outbound_security to registry strings.
    SECURITY_TO_REG = {
      'none'    => 'None',
      'require' => 'Require',
      'request' => 'Request',
    }.freeze

    # Maps Puppet phase1auth_set to registry Auth1= strings.
    PHASE1AUTH_TO_REG = {
      'none'             => nil,             # field omitted
      'default'          => 'Default',
      'computerkerberos' => 'ComputerKerb',
      'anonymous'        => 'Anonymous',
    }.freeze

    # Maps Puppet phase2auth_set to registry Auth2= strings.
    PHASE2AUTH_TO_REG = {
      'none'         => nil,                 # field omitted
      'default'      => 'Default',
      'userkerberos' => 'UserKerb',
    }.freeze

    # Named ports that require specific casing in the registry format.
    PORT_NAME_TO_REG = {
      'rpc'      => 'RPC',
      'rpcepmap' => 'RpcEpMap',
      'teredo'   => 'Teredo',
      'iphttps'  => 'IPHTTPSIn',
    }.freeze

    def self.create_rule(resource)
      Puppet.notice("(windows_firewall_ipsec_registry) adding rule '#{resource[:name]}'")
      value = build_registry_value(resource)
      Puppet.debug("(windows_firewall_ipsec_registry) writing registry value: #{value}")
      write_registry_value(resource[:name], value)
    end

    def self.update_rule(resource)
      Puppet.notice("(windows_firewall_ipsec_registry) updating rule '#{resource[:name]}'")
      value = build_registry_value(resource)
      Puppet.debug("(windows_firewall_ipsec_registry) writing registry value: #{value}")
      write_registry_value(resource[:name], value)
    end

    def self.delete_rule(resource)
      name = resource.is_a?(Hash) ? resource[:name] : resource[:name]
      Puppet.notice("(windows_firewall_ipsec_registry) deleting rule '#{name}'")
      delete_registry_value(name)
    end

    # Writes (creates or replaces) a REG_SZ value in the connection security rules key.
    def self.write_registry_value(name, value)
      require 'win32/registry'
      Win32::Registry::HKEY_LOCAL_MACHINE.open(
        CONNECTION_SECURITY_RULES_PATH,
        Win32::Registry::KEY_SET_VALUE,
      ) do |reg|
        reg[name, Win32::Registry::REG_SZ] = value
      end
    rescue Win32::Registry::Error => e
      raise Puppet::Error, "Failed to write Windows Firewall IPSec registry rule '#{name}': #{e.message}"
    end

    # Deletes a REG_SZ value from the connection security rules key.
    def self.delete_registry_value(name)
      require 'win32/registry'
      Win32::Registry::HKEY_LOCAL_MACHINE.open(
        CONNECTION_SECURITY_RULES_PATH,
        Win32::Registry::KEY_SET_VALUE,
      ) do |reg|
        reg.delete_value(name)
      end
    rescue Win32::Registry::Error => e
      raise Puppet::Error, "Failed to delete Windows Firewall IPSec registry rule '#{name}': #{e.message}"
    end

    # Constructs the pipe-delimited registry string for an IPSec connection security
    # rule resource.  The format follows the Windows Firewall v2.31 schema used in:
    #   HKLM\...\FirewallPolicy\ConnectionSecurityRules
    def self.build_registry_value(resource)
      parts = ['v2.31']

      # Connection security rules always use Action=ConSecRule (no Allow/Block).
      parts << 'Action=ConSecRule'
      parts << "Active=#{resource[:enabled] == :true ? 'TRUE' : 'FALSE'}"

      # IPSec rules are bidirectional — Dir is always Both.
      parts << 'Dir=Both'

      # Protocol — numeric IANA value (protocol is required for IPSec rules).
      protocol = resource[:protocol].to_s
      parts << "Protocol=#{PROTOCOL_TO_REG.fetch(protocol, protocol)}"

      # --- Ports ---
      local_ports  = Array(resource[:local_port]).map(&:to_s)
      remote_ports = Array(resource[:remote_port]).map(&:to_s)
      parts << "LPort=#{ports_to_reg(local_ports)}"
      parts << "RPort=#{ports_to_reg(remote_ports)}"

      # --- Addresses ---
      local_addrs  = Array(resource[:local_address]).map(&:to_s)
      remote_addrs = Array(resource[:remote_address]).map(&:to_s)
      parts << "LA4=#{addrs_to_reg(local_addrs)}"
      parts << "RA4=#{addrs_to_reg(remote_addrs)}"

      # --- Profile ---
      profiles = Array(resource[:profile]).map { |p| PROFILE_TO_REG[p.to_s] }.compact
      profile_str = if profiles.empty? || profiles.include?('Any')
                      'Any'
                    else
                      profiles.join(',')
                    end
      parts << "Profile=#{profile_str}"

      # --- Interface type ---
      if_types = Array(resource[:interface_type]).map { |t| INTERFACE_TYPE_TO_REG[t.to_s] }.compact
      if_str = if_types.empty? || if_types.include?('Any') ? 'Any' : if_types.join(',')
      parts << "IF=#{if_str}"

      # --- IPSec-specific fields ---

      # Mode (transport / tunnel / none)
      mode = MODE_TO_REG[resource[:mode].to_s] || 'Transport'
      parts << "Mode=#{mode}"

      # Inbound / outbound security
      inbound_sec  = SECURITY_TO_REG[resource[:inbound_security].to_s]  || 'None'
      outbound_sec = SECURITY_TO_REG[resource[:outbound_security].to_s] || 'None'
      parts << "InboundSec=#{inbound_sec}"
      parts << "OutboundSec=#{outbound_sec}"

      # Phase 1 authentication set (main mode / IKE)
      auth1 = PHASE1AUTH_TO_REG[resource[:phase1auth_set].to_s]
      parts << "Auth1=#{auth1}" if auth1

      # Phase 2 authentication set (quick mode / IKE)
      auth2 = PHASE2AUTH_TO_REG[resource[:phase2auth_set].to_s]
      parts << "Auth2=#{auth2}" if auth2

      # --- Display name and description ---
      display_name = resource[:display_name].to_s
      display_name = resource[:name].to_s if display_name.empty?
      parts << "Name=#{display_name}"
      parts << "Desc=#{resource[:description] || ''}"

      parts.join('|') + '|'
    end

    # Converts an array of port values to the registry string format.
    # Returns 'Any' when the list is empty or contains only 'any'.
    def self.ports_to_reg(ports)
      effective = ports.reject { |p| p.to_s.downcase == 'any' }
      return 'Any' if effective.empty?

      effective.map { |p| PORT_NAME_TO_REG.fetch(p.to_s.downcase, p.to_s) }.join(',')
    end

    # Converts an array of address values to the registry string format.
    # Returns 'Any' when the list is empty or contains only 'any'.
    def self.addrs_to_reg(addrs)
      effective = addrs.reject { |a| a.to_s.downcase == 'any' }
      return 'Any' if effective.empty?

      effective.join(',')
    end
  end
end
