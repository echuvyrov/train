# encoding: utf-8

require 'digest/sha1'

module Train::Platforms
  class UUID
    def initialize(platform)
      @platform = platform
      @backend = @platform.backend
    end

    def find_or_create_uuid
      if @platform.unix?
        unix
      elsif @platform.windows?
        windows
      elsif @platform.aws?
        aws
      end
    end

    private

    def aws
      #something
    end

    def windows
      # check for chef uuid
      result = @backend.run_command("type #{ENV['SYSTEMDRIVE']}\\chef\\cache\\data_collector_metadata.json")
      if result.exit_status == 0 && !result.stdout.nil?
        json = JSON.parse(result.stdout.chomp)
        return json['node_uuid'] if json['node_uuid']
      end

      result = @backend.run_command("wmic csproduct get UUID")
      return result.stdout.split("\r\n")[-1].strip.downcase if result.exit_status == 0

      cmd = '(Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid")."MachineGuid"'
      result = @backend.run_command(cmd)
      return result.stdout.chomp.downcase if result.exit_status == 0

      # see if we have a custom uuid
      uuid_path = "#{ENV['SYSTEMROOT']}\\machine-uuid"
      result = @backend.run_command("type #{uuid_path}")
      return result.stdout.chomp if result.exit_status == 0 && !result.stdout.nil?

      # cant find anything, try to write a uuid
      uuid = SecureRandom.uuid
      result = @backend.run_command("'#{uuid}' >> #{uuid_path}")
      raise "Cannot write uuid to `#{uuid_path}`" if result.exit_status !=0
      uuid
    end


    def unix
      # check for chef uuid
      file = @backend.file('/var/chef/cache/data_collector_metadata.json')
      if file.exist?
        json = JSON.parse(file.content)
        return json['node_uuid'] if json['node_uuid']
      end

      # check for standard machine-ids
      %w(
        /etc/machine-id
        /var/lib/dbus/machine-id
        /var/db/dbus/machine-id
        /etc/machine-uuid
      ).each do |path|
        file = @backend.file(path)
        return uuid_from_string(file.content) if file.exist? && file.size != 0
      end

      if @platform[:uuid_command]
        result = @backend.run_command(@platform[:uuid_command])
        return result.stdout.chomp if result.exit_status == 0 && !result.stdout.nil?
      end

      # cant find anything, try to write a config
      uuid = SecureRandom.uuid
      result = @backend.run_command("echo \"#{uuid}\" > /etc/machine-uuid")
      raise 'Cannot write uuid to `/etc/machine-uuid`' if result.exit_status !=0
      uuid
    end

    def uuid_from_string(string)
      hash = Digest::SHA1.new
      hash.update(string)
      ary = hash.digest.unpack("NnnnnN")
      ary[2] = (ary[2] & 0x0FFF) | (5 << 12)
      ary[3] = (ary[3] & 0x3FFF) | 0x8000
      "%08x-%04x-%04x-%04x-%04x%08x" % ary
    end
  end
end
