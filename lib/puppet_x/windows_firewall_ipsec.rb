require 'puppet_x'
require 'pp'

# This module manage Windows Firewall IPSec rules
module PuppetX::WindowsFirewallIPSec
  MOD_DIR = 'windows_firewall/lib'.freeze
  SCRIPT_FILE = 'ps-bridge-ipsec.ps1'.freeze
  SCRIPT_PATH = File.join('ps/windows_firewall', SCRIPT_FILE)

  # We need to be able to invoke the PS bridge script in both agent and apply
  # mode. In agent mode, the file will be found in LIBDIR, in apply mode it will
  # be found somewhere under CODEDIR. We need to read from the appropriate dir
  # for each mode to work in the most puppety way
  def self.resolve_ps_bridge
    case Puppet.run_mode.name
    when :user
      # AKA `puppet resource` - first scan modules then cache
      script = find_ps_bridge_in_modules || find_ps_bridge_in_cache
    when :apply
      # puppet apply demands local module install...
      script = find_ps_bridge_in_modules
    when :agent
      # agent mode would only look in cache
      script = find_ps_bridge_in_cache
    else
      raise("Don't know how to resolve #{SCRIPT_FILE} for windows_firewall in mode #{Puppet.run_mode.name}")
    end

    unless script
      raise("windows_firewall unable to find #{SCRIPT_FILE} in expected location")
    end

    cmd = ['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', script]
    cmd
  end

  def self.find_ps_bridge_in_modules
    # 1st priority - environment
    check_for_script = File.join(
        Puppet.settings[:environmentpath],
        Puppet.settings[:environment],
        'modules',
        MOD_DIR,
        SCRIPT_PATH,
      )
    Puppet.debug("Checking for #{SCRIPT_FILE} at #{check_for_script}")
    if File.exist? check_for_script
      script = check_for_script
    else
      # 2nd priority - custom module path, then basemodulepath
      full_module_path = "#{Puppet.settings[:modulepath]}#{File::PATH_SEPARATOR}#{Puppet.settings[:basemodulepath]}"
      full_module_path.split(File::PATH_SEPARATOR).reject { |path_element|
        path_element.empty?
      }.each do |path_element|
        check_for_script = File.join(path_element, MOD_DIR, SCRIPT_PATH)
        Puppet.debug("Checking for #{SCRIPT_FILE} at #{check_for_script}")
        if File.exist? check_for_script
          script = check_for_script
          break
        end
      end
    end

    script
  end

  def self.find_ps_bridge_in_cache
    check_for_script = File.join(Puppet.settings[:libdir], SCRIPT_PATH)

    Puppet.debug("Checking for #{SCRIPT_FILE} at #{check_for_script}")
    script = File.exist?(check_for_script) ? check_for_script : nil
    script
  end

  def self.to_ps(key)
    {
      enabled: ->(x) { camel_case(x) },
      action: ->(x) { camel_case(x) },
      description: ->(x) { (x.empty? == true) ? "\"#{x}\"" : x },
      interface_type: ->(x) { x.map { |e| camel_case(e) }.join(',') },
      profile: ->(x) { x.map { |e| camel_case(e) }.join(',') },
      protocol: ->(x) { x.to_s.upcase.sub('V', 'v') },
      local_port: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      remote_port: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      local_address: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      remote_address: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      mode: ->(x) { camel_case(x) },
      inbound_security: ->(x) { camel_case(x) },
      outbound_security: ->(x) { camel_case(x) },
      phase1auth_set: ->(x) { camel_case(x) },
      phase2auth_set: ->(x) { camel_case(x) },
    }.fetch(key, ->(x) { x })
  end

  def self.to_ruby(key)
    {
      enabled: ->(x) { snake_case_sym(x) },
      action: ->(x) { snake_case_sym(x) },
      interface_type: ->(x) { x.split(',').map { |e| snake_case_sym(e.strip) } },
      profile: ->(x) { x.split(',').map { |e| snake_case_sym(e.strip) } },
      protocol: ->(x) { snake_case_sym(x) },
      remote_port: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      local_port: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      remote_address: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      local_address: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      mode: ->(x) { x.downcase },
      inbound_security: ->(x) { x.downcase },
      outbound_security: ->(x) { x.downcase },
      phase1auth_set: ->(x) { x.downcase },
      phase2auth_set: ->(x) { x.downcase },
    }.fetch(key, ->(x) { x })
  end

  # create a normalised key name by:
  # 1. lowercasing input
  # 2. converting spaces to underscores
  # 3. convert to symbol
  def self.key_name(input)
    input.downcase.gsub(%r{\s}, '_').to_sym
  end

  # Convert input CamelCase to snake_case symbols
  def self.snake_case_sym(input)
    input.gsub(%r{([a-z])([A-Z])}, '\1_\2').downcase.to_sym
  end

  # Convert snake_case input symbol to CamelCase string
  def self.camel_case(input)
    # https://stackoverflow.com/a/24917606/3441106
    input.to_s.split('_').map(&:capitalize).join
  end

  def self.delete_rule(resource)
    Puppet.notice("(windows_firewall) deleting ipsec rule '#{resource[:display_name]}'")
    out = Puppet::Util::Execution.execute(resolve_ps_bridge + ['delete', resource[:name]]).to_s
    Puppet.debug out
  end

  def self.update_rule(resource)
    Puppet.notice("(windows_firewall) updating ipsec rule '#{resource[:display_name]}'")

    # `Name` is mandatory and also a `parameter` not a `property`
    args = [ '-Name', resource[:name] ]

    resource.properties.reject { |property|
      [:ensure, :protocol_type, :protocol_code].include?(property.name)
    }.each do |property|
      # All properties start `-`
      property_name = "-#{camel_case(property.name)}"
      property_value = to_ps(property.name).call(property.value)

      # protocol can optionally specify type and code, other properties are set very simply
      args << property_name
      args << property_value
    end
    Puppet.debug "Updating firewall ipsec rule with args: #{args}"

    out = Puppet::Util::Execution.execute(resolve_ps_bridge + ['update'] + args)
    Puppet.debug out
  end

  # Create a new firewall rule using powershell
  # @see https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=win10-ps
  def self.create_rule(resource)
    Puppet.notice("(windows_firewall) adding ipsec rule '#{resource[:display_name]}'")

    # `Name` is mandatory and also a `parameter` not a `property`
    args = [ '-Name', resource[:name] ]

    resource.properties.reject { |property|
      [:ensure, :protocol_type, :protocol_code].include?(property.name)
    }.each do |property|
      # All properties start `-`
      property_name = "-#{camel_case(property.name)}"
      property_value = to_ps(property.name).call(property.value)

      # protocol can optionally specify type and code, other properties are set very simply
      args << property_name
      args << property_value
    end
    Puppet.debug "Creating firewall ipsec rule with args: #{args}"

    out = Puppet::Util::Execution.execute(resolve_ps_bridge + ['create'] + args)
    Puppet.debug out
  end

  def self.rules
    Puppet.debug('query all ipsec rules')
    rules = JSON.parse Puppet::Util::Execution.execute(resolve_ps_bridge + ['show']).to_s

    # Rules is an array of hash as-parsed and hash keys need converted to
    # lowercase ruby labels
    puppet_rules = rules.map do |e|
      Hash[e.map do |k, v|
        key = snake_case_sym(k)
        [key, to_ruby(key).call(v)]
      end].merge({ ensure: :present })
    end
    Puppet.debug("Parsed ipsec rules: #{puppet_rules.size}")
    puppet_rules
  end

  # Each rule is se
  def self.parse_profile(input)
    profile = {}
    first_line = true
    profile_name = '__error__'
    input.split("\n").reject { |line|
      line.include?('---') || line =~ %r{^\s*$}
    }.each do |line|
      if first_line
        # take the first word in the line - eg "public profile settings" -> "public"
        profile_name = line.split(' ')[0].downcase
        first_line = false
      else
        # nasty hack - "firewall policy" setting contains space and will break our
        # logic below. Also the setter in `netsh` to use is `firewallpolicy`. Just fix it...
        line = line.sub('Firewall Policy', 'firewallpolicy')

        # split each line at most twice by first glob of whitespace
        line_split = line.split(%r{\s+}, 2)

        if line_split.size == 2
          key = key_name(line_split[0].strip)

          # downcase all values for comparison purposes
          value = line_split[1].strip.downcase

          profile[key] = value
        end
      end
    end

    # if we see the rule then it must exist...
    profile[:name] = profile_name

    Puppet.debug "Parsed windows firewall profile: #{profile}"
    profile
  end

  # Each rule is se
  def self.parse_global(input)
    globals = {}
    input.split("\n").reject { |line|
      line.include?('---') || line =~ %r{^\s*$}
    }.each do |line|
      # split each line at most twice by first glob of whitespace
      line_split = line.split(%r{\s+}, 2)

      next unless line_split.size == 2
      key = key_name(line_split[0].strip)

      # downcase all values for comparison purposes
      value = line_split[1].strip.downcase

      safe_value = case key
                   when :secmethods
                     # secmethods are output with a hypen like this:
                     #   DHGroup2-AES128-SHA1,DHGroup2-3DES-SHA1
                     # but must be input with a colon like this:
                     #   DHGroup2:AES128-SHA1,DHGroup2:3DES-SHA1
                     value.split(',').map { |e|
                       e.sub('-', ':')
                     }.join(',')
                   when :strongcrlcheck
                     value.split(':')[0]
                   when :defaultexemptions
                     value.split(',').sort
                   when :saidletimemin
                     value.sub('min', '')
                   when :ipsecthroughnat
                     value.delete(' ')
                   else
                     value
                   end

      globals[key] = safe_value
    end

    globals[:name] = 'global'

    Puppet.debug "Parsed windows firewall globals: #{globals}"
    globals
  end
end
