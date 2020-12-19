require 'puppet_x'
#require 'puppet_x/windows_firewall'
require_relative '../../../puppet_x/windows_firewall'

Puppet::Type.type(:windows_firewall_rule).provide(:windows_firewall_rule, :parent => Puppet::Provider) do
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
    PuppetX::WindowsFirewall.create_rule @resource
  end

  # all work done in `flush()` method
  def destroy()
    PuppetX::WindowsFirewall.delete_rule @resource[:name]
  end

  def self.instances
    PuppetX::WindowsFirewall.rules.collect { |hash| new(hash) }
  end

  def flush
    PuppetX::WindowsFirewall.update_rule @resource
  end

end