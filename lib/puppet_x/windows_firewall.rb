require 'puppet_x'
require 'pp'
require 'puppet/util'
require 'puppet/util/windows'

# This module manage Windows Firewall rules
module PuppetX::WindowsFirewall
  MOD_DIR = 'windows_firewall/lib'.freeze
  SCRIPT_FILE = 'ps-bridge.ps1'.freeze
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

  # convert a puppet type key name to the argument to use for `netsh` command
  def self.global_argument_lookup(key)
    {
      keylifetime: 'mainmode mmkeylifetime',
        secmethods: 'mainmode mmsecmethods',
        forcedh: 'mainmode mmforcedh',
        strongcrlcheck: 'ipsec strongcrlcheck',
        saidletimemin: 'ipsec saidletimemin',
        defaultexemptions: 'ipsec defaultexemptions',
        ipsecthroughnat: 'ipsec ipsecthroughnat',
        authzcomputergrp: 'ipsec authzcomputergrp',
        authzusergrp: 'ipsec authzusergrp',
    }.fetch(key, key.to_s)
  end

  # convert a puppet type key name to the argument to use for `netsh` command
  def self.profile_argument_lookup(key)
    {
      localfirewallrules: 'settings localfirewallrules',
      localconsecrules: 'settings localconsecrules',
      inboundusernotification: 'settings inboundusernotification',
      remotemanagement: 'settings remotemanagement',
      unicastresponsetomulticast: 'settings unicastresponsetomulticast',
      logallowedconnections: 'logging allowedconnections',
      logdroppedconnections: 'logging droppedconnections',
      filename: 'logging filename',
      maxfilesize: 'logging maxfilesize',
    }.fetch(key, key.to_s)
  end

  def self.to_ps(key)
    {
      enabled: ->(x) { camel_case(x) },
      action: ->(x) { camel_case(x) },
      direction: ->(x) { camel_case(x) },
      description: ->(x) { (x.empty? == true) ? "\"#{x}\"" : x },
      interface_type: ->(x) { x.map { |e| camel_case(e) }.join(',') },
      profile: ->(x) { x.map { |e| camel_case(e) }.join(',') },
      protocol: ->(x) { x.to_s.upcase.sub('V', 'v') },
      icmp_type: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      edge_traversal_policy: ->(x) { camel_case(x) },
      local_port: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      remote_port: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      local_address: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      remote_address: ->(x) { x.is_a?(Array) ? (x.map { |e| camel_case(e) }).join(',') : camel_case(x) },
      program: ->(x) { (x.to_s == 'any') ? x : x.gsub(%r{\\}, '\\\\') },
      authentication: ->(x) { camel_case(x) },
      encryption: ->(x) { camel_case(x) },
      remote_machine: ->(x) { convert_to_sddl(x) },
      local_user: ->(x) { convert_to_sddl(x) },
      remote_user: ->(x) { convert_to_sddl(x) },
    }.fetch(key, ->(x) { x })
  end

  def self.to_ruby(key)
    {
      enabled: ->(x) { snake_case_sym(x) },
      action: ->(x) { snake_case_sym(x) },
      direction: ->(x) { snake_case_sym(x) },
      interface_type: ->(x) { x.split(',').map { |e| snake_case_sym(e.strip) } },
      profile: ->(x) { x.split(',').map { |e| snake_case_sym(e.strip) } },
      protocol: ->(x) { snake_case_sym(x) },
      icmp_type: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      edge_traversal_policy: ->(x) { snake_case_sym(x) },
      program: ->(x) { (x.to_s == 'Any') ? x.downcase : x.gsub(%r{\\\\}, '\\') },
      remote_port: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      local_port: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      remote_address: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      local_address: ->(x) { x.is_a?(Array) ? x.map { |e| e.downcase } : x.downcase.split },
      authentication: ->(x) { x.downcase },
      encryption: ->(x) { x.downcase },
      remote_machine: ->(x) { convert_from_sddl(x) },
      local_user: ->(x) { convert_from_sddl(x) },
      remote_user: ->(x) { convert_from_sddl(x) },
      service: ->(x) { x.downcase },
    }.fetch(key, ->(x) { x })
  end

  # Convert name to SID and structure result as SDDL value
  def self.convert_to_sddl_acl(value, ace)
    # we need to convert users to sids first
    sids = []
    value.split(',').sort.each do |name|
      name.strip!
      sid = Puppet::Util::Windows::SID.name_to_sid(name)
      # If resolution failed, thrown a warning
      if sid.nil?
        warn("\"#{value}\" does not exist")
      else
        # Generate structured SSDL ACL
        cur_sid = '(' + ace + ';;CC;;;' + sid + ')'
      end
      sids << cur_sid unless cur_sid.nil?
    end
    sids.sort.join('')
  end

  # Convert name to SID and structure result as SDDL value (Only if value is not any)
  def self.convert_to_sddl(value)
    if value.to_s == 'any'
      value
    else
      'O:LSD:' + (convert_to_sddl_acl(value['allow'], 'A') unless value['allow'].nil?).to_s + (convert_to_sddl_acl(value['block'], 'D') unless value['block'].nil?).to_s
    end
  end

  # Parse SDDL value and convert SID to name
  def self.convert_from_sddl(value)
    if value == 'Any'
      # Return value in lowercase
      value.downcase!
    else
      # we need to convert users to sids first
      # Delete prefix
      value.delete_prefix! 'O:LSD:'
      # Change ')(' to ',' to have a proper delimiter
      value.gsub! ')(', ','
      # Remove '()'
      value.delete! '()'
      # Define variables
      names = {}
      allow = []
      deny = []
      value.split(',').sort.each do |sid|
        # ACE is first character
        ace = sid.chr.upcase
        # Delete prefix on each user
        sid.delete_prefix! ace + ';;CC;;;'
        sid.strip!
        name = Puppet::Util::Windows::SID.sid_to_name(sid)
        # If resolution failed, return SID
        cur_name = if name.nil?
                     sid.downcase!
                   else
                     name.downcase!
                   end
        case ace
        when 'A'
          allow << cur_name unless cur_name.nil?
        when 'D'
          deny << cur_name unless cur_name.nil?
        end
      end
      unless allow.empty?
        names['allow'] = allow.sort.join(',')
      end
      unless deny.empty?
        names['block'] = deny.sort.join(',')
      end
      names
    end
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
    Puppet.notice("(windows_firewall) deleting rule '#{resource[:display_name]}'")
    out = Puppet::Util::Execution.execute(resolve_ps_bridge + ['delete', resource[:name]]).to_s
    Puppet.debug out
  end

  def self.update_rule(resource)
    Puppet.notice("(windows_firewall) updating rule '#{resource[:display_name]}'")

    # `Name` is mandatory and also a `parameter` not a `property`
    args = [ '-Name', resource[:name] ]

    resource.properties.reject { |property|
      [:ensure, :protocol_type, :protocol_code].include?(property.name) ||
        property.value == :none
    }.each do |property|
      # All properties start `-`
      property_name = "-#{camel_case(property.name)}"
      property_value = to_ps(property.name).call(property.value)

      # protocol can optionally specify type and code, other properties are set very simply
      args << property_name
      args << property_value
    end
    Puppet.debug "Updating firewall rule with args: #{args}"

    out = Puppet::Util::Execution.execute(resolve_ps_bridge + ['update'] + args)
    Puppet.debug out
  end

  # Create a new firewall rule using powershell
  # @see https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=win10-ps
  def self.create_rule(resource)
    Puppet.notice("(windows_firewall) adding rule '#{resource[:display_name]}'")

    # `Name` is mandatory and also a `parameter` not a `property`
    args = [ '-Name', resource[:name] ]

    resource.properties.reject { |property|
      [:ensure, :protocol_type, :protocol_code].include?(property.name) ||
        property.value == :none
    }.each do |property|
      # All properties start `-`
      property_name = "-#{camel_case(property.name)}"
      property_value = to_ps(property.name).call(property.value)

      # protocol can optionally specify type and code, other properties are set very simply
      args << property_name
      args << property_value
    end
    Puppet.debug "Creating firewall rule with args: #{args}"

    out = Puppet::Util::Execution.execute(resolve_ps_bridge + ['create'] + args)
    Puppet.debug out
  end

  def self.rules
    Puppet.debug('query all rules')
    rules = JSON.parse Puppet::Util::Execution.execute(resolve_ps_bridge + ['show']).to_s

    # Rules is an array of hash as-parsed and hash keys need converted to
    # lowercase ruby labels
    puppet_rules = rules.map do |e|
      Hash[e.map do |k, v|
        key = snake_case_sym(k)
        [key, to_ruby(key).call(v)]
      end].merge({ ensure: :present })
    end
    Puppet.debug("Parsed rules: #{puppet_rules.size}")
    puppet_rules
  end

  def self.groups
    Puppet.debug('query all groups')
    # get all individual firewall rules, then create a new hash containing the overall group
    # status for each group of rules
    g = {}
    rules.reject { |e|
      # we are only interested in firewall rules that provide grouping information so bounce
      # anything that doesn't have it from the list
      e[:display_group].empty?
    }.each do |e|
      # extract the group information for each rule, use the value of :enabled to
      # build up an overall status for the whole group. Dont forget that the
      # value is a label :true or :false - to fit with puppet's newtype operator
      k = e[:display_group]
      current = g.fetch(k, e[:enabled])

      g[k] = if current == :true && e[:enabled] == :true
               :true
             else
               :false
             end
    end

    # convert into puppet's preferred hash format which is an array of hashes
    # with each hash representing a distinct resource
    transformed = g.map do |k, v|
      { name: k, enabled: v }
    end

    Puppet.debug("group rules #{transformed}")
    transformed
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

  # parse firewall profiles
  def self.profiles(cmd)
    profiles = []
    # the output of `show allprofiles` contains several blank lines that make parsing somewhat
    # harder so just run it for each of the three profiles to make life easy...
    ['publicprofile', 'domainprofile', 'privateprofile'].each do |profile|
      profiles <<  parse_profile(Puppet::Util::Execution.execute([cmd, 'advfirewall', 'show', profile]).to_s)
    end
    profiles
  end

  # parse firewall profiles
  def self.globals(cmd)
    profiles = []
    # the output of `show allprofiles` contains several blank lines that make parsing somewhat
    # harder so just run it for each of the three profiles to make life easy...
    ['publicprofile', 'domainprofile', 'privateprofile'].each do |_profile|
      profiles <<  parse_global(Puppet::Util::Execution.execute([cmd, 'advfirewall', 'show', 'global']).to_s)
    end
    profiles
  end
end
