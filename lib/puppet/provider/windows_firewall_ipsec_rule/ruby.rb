require 'puppet_x'
#require 'puppet_x/windows_firewall'
require_relative '../../../puppet_x/windows_firewall_ipsec'

Puppet::Type.type(:windows_firewall_ipsec_rule).provide(:windows_firewall_ipsec_rule, :parent => Puppet::Provider) do
  confine :osfamily => :windows
  mk_resource_methods
  desc "Windows Firewall"


  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end
  
  def exists?
    @property_hash[:ensure] == :present
  end

  # all work done in `flush()` method
  def create()
    PuppetX::WindowsFirewallIPSec.create_rule @resource
  end

  # all work done in `flush()` method
  def destroy()
    PuppetX::WindowsFirewallIPSec.delete_rule @resource[:name]
  end

  def self.instances
    PuppetX::WindowsFirewallIPSec.rules.collect { |hash| new(hash) }
  end

  def flush
    PuppetX::WindowsFirewallIPSec.update_rule @resource
  end

end
