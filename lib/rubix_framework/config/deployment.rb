# Advanced configuration and deployment features
# This file contains deployment configurations, environment management, and advanced settings

require 'rubygems'
require 'yaml'
require 'json'
require 'erb'
require 'pathname'
require 'fileutils'
require 'digest'
require 'openssl'

module Rubix
  module Config
    # Advanced environment management
    class EnvironmentManager
      def initialize
        @environments = {}
        @current_env = ENV['RUBIX_ENV'] || ENV['RACK_ENV'] || 'development'
        load_environment_configs
      end

      def current
        @current_env
      end

      def set_environment(env)
        @current_env = env.to_s
        ENV['RUBIX_ENV'] = @current_env
        reload_configuration
      end

      def development?
        @current_env == 'development'
      end

      def test?
        @current_env == 'test'
      end

      def production?
        @current_env == 'production'
      end

      def staging?
        @current_env == 'staging'
      end

      def environment_config
        @environments[@current_env] || {}
      end

      def with_environment(env, &block)
        original_env = @current_env
        set_environment(env)
        begin
          block.call
        ensure
          set_environment(original_env)
        end
      end

      def available_environments
        @environments.keys
      end

      private

      def load_environment_configs
        config_dir = 'config/environments'

        return unless Dir.exist?(config_dir)

        Dir.glob("#{config_dir}/*.yml").each do |file|
          env_name = File.basename(file, '.yml')
          @environments[env_name] = YAML.load_file(file) || {}
        end

        # Load Ruby config files
        Dir.glob("#{config_dir}/*.rb").each do |file|
          env_name = File.basename(file, '.rb')
          @environments[env_name] ||= {}
          load file
        end
      end

      def reload_configuration
        # Reload all configuration files for the new environment
        Rubix::Config::Loader.reload! if defined?(Rubix::Config::Loader)
      end
    end

    # Configuration templating
    class TemplateEngine
      def initialize(template_dir = 'config/templates')
        @template_dir = template_dir
        @cache = {}
      end

      def render(template_name, variables = {})
        template_path = find_template(template_name)
        return nil unless template_path

        template_content = load_template(template_path)
        process_template(template_content, variables)
      end

      def render_to_file(template_name, output_path, variables = {})
        content = render(template_name, variables)
        return false unless content

        FileUtils.mkdir_p(File.dirname(output_path))
        File.write(output_path, content)
        true
      end

      def available_templates
        Dir.glob("#{@template_dir}/**/*").select { |f| File.file?(f) }.map do |file|
          Pathname.new(file).relative_path_from(Pathname.new(@template_dir)).to_s
        end
      end

      private

      def find_template(name)
        possible_paths = [
          "#{@template_dir}/#{name}",
          "#{@template_dir}/#{name}.erb",
          "#{@template_dir}/#{name}.yml.erb",
          "#{@template_dir}/#{name}.json.erb"
        ]

        possible_paths.find { |path| File.exist?(path) }
      end

      def load_template(path)
        @cache[path] ||= File.read(path)
      end

      def process_template(content, variables)
        if content.include?('<%=') || content.include?('<%')
          # ERB template
          erb = ERB.new(content)
          erb.result_with_hash(variables)
        else
          # Simple variable substitution
          variables.each do |key, value|
            content.gsub!("{{#{key}}}", value.to_s)
            content.gsub!("${#{key}}", value.to_s)
          end
          content
        end
      end
    end

    # Configuration encryption
    class Encryptor
      def initialize(key = nil)
        @key = key || ENV['RUBIX_CONFIG_KEY'] || generate_key
        @cipher = OpenSSL::Cipher.new('aes-256-gcm')
      end

      def encrypt(plaintext)
        @cipher.encrypt
        @cipher.key = @key

        iv = @cipher.random_iv
        @cipher.iv = iv

        encrypted = @cipher.update(plaintext) + @cipher.final
        tag = @cipher.auth_tag

        # Return base64 encoded iv + encrypted data + auth tag
        Base64.encode64(iv + encrypted + tag).strip
      end

      def decrypt(ciphertext)
        data = Base64.decode64(ciphertext)

        # Extract iv, encrypted data, and auth tag
        iv = data[0...@cipher.iv_len]
        tag_start = data.length - 16
        encrypted = data[@cipher.iv_len...tag_start]
        tag = data[tag_start..-1]

        @cipher.decrypt
        @cipher.key = @key
        @cipher.iv = iv
        @cipher.auth_tag = tag

        @cipher.update(encrypted) + @cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise DecryptionError, "Failed to decrypt configuration data"
      end

      def encrypt_file(input_path, output_path = nil)
        output_path ||= "#{input_path}.enc"

        plaintext = File.read(input_path)
        encrypted = encrypt(plaintext)

        File.write(output_path, encrypted)
        output_path
      end

      def decrypt_file(input_path, output_path = nil)
        output_path ||= input_path.sub('.enc', '.dec')

        ciphertext = File.read(input_path)
        decrypted = decrypt(ciphertext)

        File.write(output_path, decrypted)
        output_path
      end

      private

      def generate_key
        OpenSSL::Random.random_bytes(32)
      end

      class DecryptionError < StandardError; end
    end

    # Configuration validation with schemas
    class SchemaValidator
      def initialize(schema)
        @schema = schema.deep_symbolize_keys
      end

      def validate(config)
        errors = []
        validate_against_schema(@schema, config, '', errors)
        errors
      end

      def validate!(config)
        errors = validate(config)
        raise ValidationError.new(errors) if errors.any?
        true
      end

      private

      def validate_against_schema(schema, data, path, errors)
        schema.each do |key, rules|
          key_path = path.empty? ? key.to_s : "#{path}.#{key}"

          if rules['required'] && !data.key?(key)
            errors << "#{key_path} is required"
            next
          end

          next unless data.key?(key)

          value = data[key]

          validate_type(value, rules['type'], key_path, errors)
          validate_constraints(value, rules, key_path, errors)

          if rules['type'] == 'object' && rules['properties']
            validate_against_schema(rules['properties'], value, key_path, errors)
          elsif rules['type'] == 'array' && rules['items'] && value.is_a?(Array)
            value.each_with_index do |item, index|
              item_path = "#{key_path}[#{index}]"
              if rules['items'].is_a?(Hash)
                validate_against_schema({ 'item' => rules['items'] }, { 'item' => item }, item_path, errors)
              end
            end
          end
        end
      end

      def validate_type(value, expected_type, path, errors)
        return unless expected_type

        case expected_type
        when 'string'
          errors << "#{path} must be a string" unless value.is_a?(String)
        when 'number'
          errors << "#{path} must be a number" unless value.is_a?(Numeric)
        when 'integer'
          errors << "#{path} must be an integer" unless value.is_a?(Integer)
        when 'boolean'
          errors << "#{path} must be true or false" unless [true, false].include?(value)
        when 'object'
          errors << "#{path} must be an object" unless value.is_a?(Hash)
        when 'array'
          errors << "#{path} must be an array" unless value.is_a?(Array)
        end
      end

      def validate_constraints(value, rules, path, errors)
        if rules['minimum'] && value.is_a?(Numeric)
          errors << "#{path} must be at least #{rules['minimum']}" if value < rules['minimum']
        end

        if rules['maximum'] && value.is_a?(Numeric)
          errors << "#{path} must be at most #{rules['maximum']}" if value > rules['maximum']
        end

        if rules['minLength'] && value.is_a?(String)
          errors << "#{path} must be at least #{rules['minLength']} characters" if value.length < rules['minLength']
        end

        if rules['maxLength'] && value.is_a?(String)
          errors << "#{path} must be at most #{rules['maxLength']} characters" if value.length > rules['maxLength']
        end

        if rules['pattern'] && value.is_a?(String)
          errors << "#{path} must match pattern #{rules['pattern']}" unless value.match?(Regexp.new(rules['pattern']))
        end

        if rules['enum'] && rules['enum'].is_a?(Array)
          errors << "#{path} must be one of: #{rules['enum'].join(', ')}" unless rules['enum'].include?(value)
        end
      end

      class ValidationError < StandardError
        attr_reader :errors

        def initialize(errors)
          @errors = errors
          super("Configuration validation failed: #{errors.join(', ')}")
        end
      end
    end

    # Deployment configuration
    class DeploymentConfig
      def initialize(config_file = 'config/deploy.yml')
        @config_file = config_file
        @config = load_config
      end

      def servers(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'servers') || []
      end

      def database_config(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'database') || {}
      end

      def app_config(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'application') || {}
      end

      def deployment_strategy(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'strategy') || 'rolling'
      end

      def pre_deploy_tasks(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'pre_deploy') || []
      end

      def post_deploy_tasks(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'post_deploy') || []
      end

      def rollback_strategy(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'rollback') || 'immediate'
      end

      def monitoring_config(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'monitoring') || {}
      end

      def backup_config(environment = nil)
        env = environment || EnvironmentManager.new.current
        @config.dig('environments', env, 'backup') || {}
      end

      private

      def load_config
        return {} unless File.exist?(@config_file)

        YAML.load_file(@config_file) || {}
      end
    end

    # Feature flags
    class FeatureFlags
      def initialize(config_file = 'config/features.yml')
        @config_file = config_file
        @flags = load_flags
        @overrides = {}
      end

      def enabled?(feature_name, context = {})
        return @overrides[feature_name] if @overrides.key?(feature_name)

        flag_config = @flags[feature_name.to_s]
        return false unless flag_config

        evaluate_conditions(flag_config, context)
      end

      def disabled?(feature_name, context = {})
        !enabled?(feature_name, context)
      end

      def override(feature_name, enabled)
        @overrides[feature_name.to_s] = enabled
      end

      def remove_override(feature_name)
        @overrides.delete(feature_name.to_s)
      end

      def clear_overrides
        @overrides.clear
      end

      def all_flags
        @flags.keys
      end

      def enabled_flags(context = {})
        @flags.select { |name, _| enabled?(name, context) }.keys
      end

      private

      def load_flags
        return {} unless File.exist?(@config_file)

        YAML.load_file(@config_file) || {}
      end

      def evaluate_conditions(flag_config, context)
        return flag_config['enabled'] if flag_config.key?('enabled')

        if flag_config['conditions']
          evaluate_conditions_hash(flag_config['conditions'], context)
        else
          false
        end
      end

      def evaluate_conditions_hash(conditions, context)
        conditions.all? do |key, value|
          case key
          when 'environment'
            EnvironmentManager.new.current == value
          when 'user_id'
            context[:user_id] == value
          when 'user_role'
            context[:user_roles]&.include?(value)
          when 'percentage'
            user_percentage(context[:user_id] || 'anonymous') <= value
          else
            context[key.to_sym] == value
          end
        end
      end

      def user_percentage(identifier)
        # Simple hash-based percentage for canary releases
        Digest::MD5.hexdigest(identifier).to_i(16) % 100
      end
    end

    # Configuration history and versioning
    class ConfigHistory
      def initialize(storage_path = 'config/history')
        @storage_path = storage_path
        @current_version = load_current_version
        FileUtils.mkdir_p(@storage_path)
      end

      def save_version(config, description = '')
        @current_version += 1

        version_data = {
          version: @current_version,
          timestamp: Time.now,
          description: description,
          config: config,
          checksum: Digest::SHA256.hexdigest(config.to_json)
        }

        save_version_file(version_data)
        update_current_version(@current_version)

        @current_version
      end

      def get_version(version_number)
        version_file = "#{@storage_path}/#{version_number}.yml"
        return nil unless File.exist?(version_file)

        YAML.load_file(version_file)
      end

      def list_versions(limit = 10)
        Dir.glob("#{@storage_path}/*.yml")
           .map { |f| File.basename(f, '.yml').to_i }
           .sort
           .reverse
           .first(limit)
      end

      def rollback_to(version_number)
        version_data = get_version(version_number)
        return false unless version_data

        # Apply the configuration from the specified version
        apply_config(version_data['config'])
        true
      end

      def diff_versions(version1, version2)
        v1_data = get_version(version1)
        v2_data = get_version(version2)

        return nil unless v1_data && v2_data

        # Generate diff between configurations
        generate_config_diff(v1_data['config'], v2_data['config'])
      end

      def current_version
        @current_version
      end

      private

      def load_current_version
        version_file = "#{@storage_path}/current_version.txt"
        return 0 unless File.exist?(version_file)

        File.read(version_file).to_i
      end

      def save_version_file(version_data)
        version_file = "#{@storage_path}/#{version_data[:version]}.yml"
        File.write(version_file, version_data.to_yaml)
      end

      def update_current_version(version)
        version_file = "#{@storage_path}/current_version.txt"
        File.write(version_file, version.to_s)
      end

      def apply_config(config)
        # This would need to be integrated with the configuration system
        # For now, just return the config
        config
      end

      def generate_config_diff(config1, config2)
        # Simple diff implementation
        # In a real implementation, you'd use a proper diff library
        {
          added: config2.keys - config1.keys,
          removed: config1.keys - config2.keys,
          changed: config1.keys & config2.keys
        }
      end
    end

    # Configuration monitoring
    class ConfigMonitor
      def initialize
        @change_callbacks = []
        @last_checksums = {}
      end

      def watch_config(config_name, config_data)
        current_checksum = Digest::SHA256.hexdigest(config_data.to_json)

        if @last_checksums[config_name] && @last_checksums[config_name] != current_checksum
          notify_change(config_name, config_data)
        end

        @last_checksums[config_name] = current_checksum
      end

      def on_change(&block)
        @change_callbacks << block
      end

      def check_all_configs(configs)
        configs.each do |name, data|
          watch_config(name, data)
        end
      end

      private

      def notify_change(config_name, new_config)
        @change_callbacks.each do |callback|
          callback.call(config_name, new_config)
        end
      end
    end
  end
end
