require 'puppet_x'
require 'puppet/util'

# Manages Windows Firewall rules by writing directly to the registry.
#
# Rules are stored as REG_SZ values under:
#   HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
#
# Each value name is the rule's Name (namevar) and the data is a pipe-delimited
# string in the Windows Firewall v2.31 format, e.g.:
#   v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=443|RA4=Any|Name=My Rule|Desc=|
#
# Windows Firewall monitors this registry key and exposes all values through the
# NetSecurity PowerShell module, so rule discovery continues to work via PowerShell.
module PuppetX
  module WindowsFirewallRegistry
    FIREWALL_RULES_PATH = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'.freeze

    # Maps Puppet protocol symbols/strings to IANA protocol numbers used in the registry.
    # When protocol is :any the field is omitted (Windows interprets absence as "any").
    PROTOCOL_TO_REG = {
      'icmpv4' => '1',
      'tcp'    => '6',
      'udp'    => '17',
      'icmpv6' => '58',
    }.freeze

    DIRECTION_TO_REG = {
      'inbound'  => 'In',
      'outbound' => 'Out',
    }.freeze

    ACTION_TO_REG = {
      'allow' => 'Allow',
      'block' => 'Block',
    }.freeze

    # Maps Puppet profile symbols to the strings used in the registry value.
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

    # Maps Puppet edge_traversal_policy to registry strings.
    EDGE_TO_REG = {
      'block'         => 'FALSE',
      'allow'         => 'TRUE',
      'defer_to_user' => 'DeferUser',
      'defer_to_app'  => 'DeferApp',
    }.freeze

    # Maps Puppet authentication to registry Security= strings.
    AUTHENTICATION_TO_REG = {
      'notrequired' => nil,              # field omitted
      'required'    => 'Authenticate',
      'noencap'     => 'AuthNoEncap',
    }.freeze

    # Maps Puppet encryption to registry Security= strings (overrides authentication when set).
    ENCRYPTION_TO_REG = {
      'notrequired' => nil,
      'required'    => 'AuthEnc',
      'dynamic'     => 'AuthDynEnc',
    }.freeze

    # Named ports that require specific casing in the registry format.
    PORT_NAME_TO_REG = {
      'rpc'      => 'RPC',
      'rpcepmap' => 'RpcEpMap',
      'teredo'   => 'Teredo',
      'iphttps'  => 'IPHTTPSIn',
      'playtodevice' => 'PlayToDevice',
    }.freeze

    def self.create_rule(resource)
      Puppet.notice("(windows_firewall_registry) adding rule '#{resource[:name]}'")
      value = build_registry_value(resource)
      Puppet.debug("(windows_firewall_registry) writing registry value: #{value}")
      write_registry_value(resource[:name], value)
    end

    def self.update_rule(resource)
      Puppet.notice("(windows_firewall_registry) updating rule '#{resource[:name]}'")
      value = build_registry_value(resource)
      Puppet.debug("(windows_firewall_registry) writing registry value: #{value}")
      write_registry_value(resource[:name], value)
    end

    def self.delete_rule(resource)
      name = resource.is_a?(Hash) ? resource[:name] : resource[:name]
      Puppet.notice("(windows_firewall_registry) deleting rule '#{name}'")
      delete_registry_value(name)
    end

    # Writes (creates or replaces) a REG_SZ value in the firewall rules key.
    def self.write_registry_value(name, value)
      require 'win32/registry'
      Win32::Registry::HKEY_LOCAL_MACHINE.open(
        FIREWALL_RULES_PATH,
        Win32::Registry::KEY_SET_VALUE,
      ) do |reg|
        reg[name, Win32::Registry::REG_SZ] = value
      end
    rescue Win32::Registry::Error => e
      raise Puppet::Error, "Failed to write Windows Firewall registry rule '#{name}': #{e.message}"
    end

    # Deletes a REG_SZ value from the firewall rules key.
    def self.delete_registry_value(name)
      require 'win32/registry'
      Win32::Registry::HKEY_LOCAL_MACHINE.open(
        FIREWALL_RULES_PATH,
        Win32::Registry::KEY_SET_VALUE,
      ) do |reg|
        reg.delete_value(name)
      end
    rescue Win32::Registry::Error => e
      raise Puppet::Error, "Failed to delete Windows Firewall registry rule '#{name}': #{e.message}"
    end

    # Constructs the pipe-delimited registry string for a firewall rule resource.
    # The format follows the Windows Firewall v2.31 schema used in:
    #   HKLM\...\FirewallPolicy\FirewallRules
    def self.build_registry_value(resource)
      parts = ['v2.31']

      # --- Required fields ---
      parts << "Action=#{ACTION_TO_REG[resource[:action].to_s] || 'Allow'}"
      parts << "Active=#{resource[:enabled] == :true ? 'TRUE' : 'FALSE'}"
      parts << "Dir=#{DIRECTION_TO_REG[resource[:direction].to_s] || 'In'}"

      # Protocol — omitted for 'any' (absence means no protocol restriction)
      protocol = resource[:protocol].to_s
      unless protocol == 'any'
        # Known names are mapped to IANA numbers; numeric values pass through unchanged
        parts << "Protocol=#{PROTOCOL_TO_REG.fetch(protocol, protocol)}"
      end

      # --- ICMP types (ICMPv4 / ICMPv6 only) ---
      if [:icmpv4, :icmpv6].include?(resource[:protocol])
        icmp_types = Array(resource[:icmp_type]).map(&:to_s).reject { |t| t == 'any' }
        parts << "ICMPTypesAndCodes=#{icmp_types.join(',')}" unless icmp_types.empty?
      end

      # --- Ports (TCP / UDP only) ---
      if [:tcp, :udp].include?(resource[:protocol])
        local_ports  = Array(resource[:local_port]).map(&:to_s)
        remote_ports = Array(resource[:remote_port]).map(&:to_s)

        lport_str = ports_to_reg(local_ports)
        rport_str = ports_to_reg(remote_ports)

        parts << "LPort=#{lport_str}"
        parts << "RPort=#{rport_str}"
      end

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

      # --- Application ---
      app = resource[:program].to_s
      parts << "App=#{(app == 'any' || app.empty?) ? 'Any' : app}"

      # --- Service ---
      svc = resource[:service].to_s
      parts << "Svc=#{(svc == 'any' || svc.empty?) ? '*' : svc}"

      # --- Rule name and description ---
      # Name= in the registry data maps to the PowerShell Name property (namevar).
      # DisplayName is handled separately by Windows based on EmbedCtxt.
      parts << "Name=#{resource[:name]}"
      parts << "Desc=#{resource[:description] || ''}"

      # --- Interface type ---
      if_types = Array(resource[:interface_type]).map { |t| INTERFACE_TYPE_TO_REG[t.to_s] }.compact
      if_str = if_types.empty? || if_types.include?('Any') ? 'Any' : if_types.join(',')
      parts << "IF=#{if_str}"

      # --- Edge traversal ---
      edge = EDGE_TO_REG[resource[:edge_traversal_policy].to_s] || 'FALSE'
      parts << "Edge=#{edge}"

      # --- Security (authentication / encryption) ---
      # Encryption takes precedence over authentication when both are specified.
      security = ENCRYPTION_TO_REG[resource[:encryption].to_s] ||
                 AUTHENTICATION_TO_REG[resource[:authentication].to_s]
      parts << "Security=#{security}" if security

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
