# Configuration management system
# This file contains configuration loaders, validators, and environment management

module Rubix
  module Config
    # Configuration loader
    class Loader
      attr_reader :config, :environment

      def initialize(environment = nil)
        @environment = environment || ENV['RUBIX_ENV'] || 'development'
        @config = {}
        @loaders = []
        @validators = []
      end

      def load_from_file(path, format = nil)
        format ||= File.extname(path)[1..-1]&.to_sym
        loader = create_loader(format)

        if loader
          file_config = loader.load(path)
          deep_merge!(@config, file_config)
        else
          raise ConfigurationError, "Unsupported configuration format: #{format}"
        end

        self
      end

      def load_from_directory(dir_path)
        Dir.glob(File.join(dir_path, '*.{yml,yaml,json,toml}')).each do |file|
          load_from_file(file)
        end

        self
      end

      def load_from_env(prefix = 'RUBIX_')
        env_config = {}

        ENV.each do |key, value|
          if key.start_with?(prefix)
            config_key = key[prefix.length..-1].downcase.split('_').join('.')
            set_nested_value(env_config, config_key, parse_env_value(value))
          end
        end

        deep_merge!(@config, env_config)
        self
      end

      def load_from_hash(hash)
        deep_merge!(@config, hash)
        self
      end

      def validate(&block)
        validator = Validator.new
        validator.instance_eval(&block)
        @validators << validator
        self
      end

      def validate!
        @validators.each do |validator|
          validator.validate(@config)
        end
        self
      end

      def to_h
        @config.dup
      end

      def [](key)
        get_nested_value(@config, key.to_s)
      end

      def []=(key, value)
        set_nested_value(@config, key.to_s, value)
      end

      def method_missing(method_name, *args)
        method_name = method_name.to_s
        if method_name.end_with?('=')
          self[method_name.chomp('=')] = args.first
        else
          self[method_name]
        end
      end

      private

      def create_loader(format)
        case format
        when :yml, :yaml
          YAMLLoader.new
        when :json
          JSONLoader.new
        when :toml
          TOMLLoader.new
        else
          nil
        end
      end

      def deep_merge!(target, source)
        source.each do |key, value|
          if target[key].is_a?(Hash) && value.is_a?(Hash)
            deep_merge!(target[key], value)
          else
            target[key] = value
          end
        end
      end

      def get_nested_value(hash, key)
        keys = key.split('.')
        keys.inject(hash) { |h, k| h[k] if h.is_a?(Hash) }
      end

      def set_nested_value(hash, key, value)
        keys = key.split('.')
        last_key = keys.pop

        nested_hash = keys.inject(hash) do |h, k|
          h[k] ||= {}
          h[k]
        end

        nested_hash[last_key] = value
      end

      def parse_env_value(value)
        case value
        when 'true', 'TRUE' then true
        when 'false', 'FALSE' then false
        when 'null', 'NULL', '' then nil
        when /^\d+$/ then value.to_i
        when /^\d+\.\d+$/ then value.to_f
        when /^\[.*\]$/ then parse_array_value(value)
        when /^\{.*\}$/ then parse_hash_value(value)
        else value
        end
      end

      def parse_array_value(value)
        value[1..-2].split(',').map(&:strip).map { |v| parse_env_value(v) }
      end

      def parse_hash_value(value)
        # Simple hash parsing: key1=value1,key2=value2
        hash = {}
        value[1..-2].split(',').each do |pair|
          key, val = pair.split('=', 2).map(&:strip)
          hash[key] = parse_env_value(val) if key && val
        end
        hash
      end

      # Configuration loaders
      class YAMLLoader
        def load(path)
          require 'yaml'
          YAML.load_file(path) || {}
        rescue Psych::SyntaxError => e
          raise ConfigurationError, "YAML syntax error in #{path}: #{e.message}"
        end
      end

      class JSONLoader
        def load(path)
          require 'json'
          JSON.parse(File.read(path), symbolize_names: true)
        rescue JSON::ParserError => e
          raise ConfigurationError, "JSON syntax error in #{path}: #{e.message}"
        end
      end

      class TOMLLoader
        def load(path)
          begin
            require 'toml'
            TOML.load_file(path)
          rescue LoadError
            raise ConfigurationError, "TOML support not available. Install the 'toml' gem."
          rescue => e
            raise ConfigurationError, "TOML parsing error in #{path}: #{e.message}"
          end
        end
      end

      # Configuration validator
      class Validator
        def initialize
          @rules = {}
        end

        def required(*keys)
          keys.each { |key| @rules[key] = :required }
        end

        def optional(*keys)
          keys.each { |key| @rules[key] = :optional }
        end

        def type(key, expected_type)
          @rules[key] = { type: expected_type }
        end

        def range(key, min: nil, max: nil)
          @rules[key] = { range: { min: min, max: max }.compact }
        end

        def inclusion(key, values)
          @rules[key] = { inclusion: values }
        end

        def format(key, regex)
          @rules[key] = { format: regex }
        end

        def custom(key, &block)
          @rules[key] = { custom: block }
        end

        def validate(config)
          errors = []

          @rules.each do |key, rule|
            value = get_nested_value(config, key.to_s)

            case rule
            when :required
              errors << "#{key} is required" if value.nil?
            when :optional
              # Optional fields are always valid
            when Hash
              if rule[:type]
                errors << "#{key} must be of type #{rule[:type]}" unless valid_type?(value, rule[:type])
              end

              if rule[:range]
                if rule[:range][:min] && value < rule[:range][:min]
                  errors << "#{key} must be >= #{rule[:range][:min]}"
                end
                if rule[:range][:max] && value > rule[:range][:max]
                  errors << "#{key} must be <= #{rule[:range][:max]}"
                end
              end

              if rule[:inclusion]
                errors << "#{key} must be one of #{rule[:inclusion].join(', ')}" unless rule[:inclusion].include?(value)
              end

              if rule[:format]
                errors << "#{key} has invalid format" unless value =~ rule[:format]
              end

              if rule[:custom]
                result = rule[:custom].call(value)
                errors << "#{key} failed custom validation" unless result
              end
            end
          end

          raise ConfigurationError, "Configuration validation failed: #{errors.join(', ')}" unless errors.empty?
        end

        private

        def get_nested_value(hash, key)
          keys = key.split('.')
          keys.inject(hash) { |h, k| h[k] if h.is_a?(Hash) }
        end

        def valid_type?(value, expected_type)
          case expected_type
          when :string then value.is_a?(String)
          when :integer then value.is_a?(Integer)
          when :float then value.is_a?(Float)
          when :boolean then [true, false].include?(value)
          when :array then value.is_a?(Array)
          when :hash then value.is_a?(Hash)
          else false
          end
        end
      end
    end

    # Environment management
    class Environment
      attr_reader :name, :config

      def initialize(name)
        @name = name
        @config = Loader.new(name)
      end

      def development?
        @name == 'development'
      end

      def test?
        @name == 'test'
      end

      def production?
        @name == 'production'
      end

      def staging?
        @name == 'staging'
      end

      def local?
        development? || test?
      end

      def remote?
        production? || staging?
      end

      def cache_enabled?
        !local?
      end

      def debug_enabled?
        development? || test?
      end

      def log_level
        case @name
        when 'development' then :debug
        when 'test' then :info
        when 'production' then :warn
        else :info
        end
      end

      def database_config
        case @name
        when 'test'
          { adapter: 'sqlite3', database: ':memory:' }
        when 'development'
          { adapter: 'sqlite3', database: 'db/development.sqlite3' }
        when 'production'
          ENV['DATABASE_URL'] || { adapter: 'postgresql', database: 'rubix_production' }
        else
          { adapter: 'sqlite3', database: "db/#{@name}.sqlite3" }
        end
      end

      def server_config
        case @name
        when 'development'
          { port: 3000, host: 'localhost', reload: true }
        when 'test'
          { port: 3001, host: 'localhost' }
        when 'production'
          { port: ENV.fetch('PORT', 3000), host: '0.0.0.0' }
        else
          { port: 3000, host: '0.0.0.0' }
        end
      end

      def cache_config
        case @name
        when 'test'
          { store: :memory, ttl: 0 }
        when 'development'
          { store: :memory, ttl: 300 }
        when 'production'
          { store: :redis, ttl: 3600, url: ENV['REDIS_URL'] }
        else
          { store: :memory, ttl: 600 }
        end
      end

      def session_config
        case @name
        when 'test'
          { store: :memory, ttl: 3600, secure: false }
        when 'development'
          { store: :memory, ttl: 86400, secure: false }
        when 'production'
          { store: :redis, ttl: 86400, secure: true, url: ENV['REDIS_URL'] }
        else
          { store: :memory, ttl: 86400, secure: true }
        end
      end

      def mail_config
        case @name
        when 'test'
          { delivery_method: :test }
        when 'development'
          { delivery_method: :smtp, smtp: { host: 'localhost', port: 1025 } }
        when 'production'
          {
            delivery_method: :smtp,
            smtp: {
              host: ENV['SMTP_HOST'],
              port: ENV['SMTP_PORT'] || 587,
              user_name: ENV['SMTP_USERNAME'],
              password: ENV['SMTP_PASSWORD']
            }
          }
        else
          { delivery_method: :smtp, smtp: { host: 'localhost', port: 587 } }
        end
      end

      def asset_config
        case @name
        when 'test'
          { compress: false, cache: false, fingerprint: false }
        when 'development'
          { compress: false, cache: false, fingerprint: false }
        when 'production'
          { compress: true, cache: true, fingerprint: true, cdn_url: ENV['CDN_URL'] }
        else
          { compress: true, cache: true, fingerprint: true }
        end
      end

      def security_config
        case @name
        when 'test'
          { csrf_protection: false, xss_protection: false, hsts: false }
        when 'development'
          { csrf_protection: true, xss_protection: true, hsts: false }
        when 'production'
          { csrf_protection: true, xss_protection: true, hsts: true }
        else
          { csrf_protection: true, xss_protection: true, hsts: false }
        end
      end

      def logging_config
        case @name
        when 'test'
          { level: :warn, format: :simple, file: nil }
        when 'development'
          { level: :debug, format: :colored, file: 'log/development.log' }
        when 'production'
          { level: :info, format: :json, file: 'log/production.log' }
        else
          { level: :info, format: :simple, file: 'log/rubix.log' }
        end
      end

      def i18n_config
        case @name
        when 'test'
          { default_locale: :en, fallbacks: false, load_path: ['config/locales'] }
        when 'development'
          { default_locale: :en, fallbacks: true, load_path: ['config/locales'] }
        when 'production'
          { default_locale: :en, fallbacks: true, load_path: ['config/locales'] }
        else
          { default_locale: :en, fallbacks: true, load_path: ['config/locales'] }
        end
      end
    end

    # Configuration manager
    class Manager
      include Singleton

      attr_reader :current_environment, :config

      def initialize
        @current_environment = Environment.new(ENV['RUBIX_ENV'] || 'development')
        @config = Loader.new(@current_environment.name)
        load_default_config
      end

      def load_default_config
        @config.load_from_hash(@current_environment.database_config)
        @config.load_from_hash(@current_environment.server_config)
        @config.load_from_hash(@current_environment.cache_config)
        @config.load_from_hash(@current_environment.session_config)
        @config.load_from_hash(@current_environment.security_config)
        @config.load_from_hash(@current_environment.logging_config)
        @config.load_from_hash(@current_environment.mail_config)
        @config.load_from_hash(@current_environment.asset_config)
        @config.load_from_hash(@current_environment.i18n_config)
      end

      def load_from_file(path)
        @config.load_from_file(path)
      end

      def load_from_directory(dir_path)
        @config.load_from_directory(dir_path)
      end

      def load_from_env(prefix = 'RUBIX_')
        @config.load_from_env(prefix)
      end

      def reload!
        @config = Loader.new(@current_environment.name)
        load_default_config
      end

      def validate(&block)
        @config.validate(&block)
      end

      def validate!
        @config.validate!
      end

      def method_missing(method_name, *args)
        @config.send(method_name, *args)
      end

      def respond_to_missing?(method_name, include_private = false)
        @config.respond_to?(method_name) || super
      end
    end

    # Configuration DSL
    module DSL
      def configure(&block)
        config = Manager.instance
        config.instance_eval(&block)
      end

      def config
        Manager.instance
      end

      def environment
        Manager.instance.current_environment
      end

      def development?
        environment.development?
      end

      def test?
        environment.test?
      end

      def production?
        environment.production?
      end

      def staging?
        environment.staging?
      end
    end

    # Encrypted configuration
    class EncryptedConfig
      def initialize(key)
        @key = key
        @config = {}
      end

      def load_from_file(path)
        encrypted_data = File.read(path)
        decrypted_data = Rubix::Utils.decrypt(encrypted_data, @key)
        @config = JSON.parse(decrypted_data, symbolize_names: true)
      end

      def save_to_file(path)
        encrypted_data = Rubix::Utils.encrypt(@config.to_json, @key)
        File.write(path, encrypted_data)
      end

      def [](key)
        @config[key]
      end

      def []=(key, value)
        @config[key] = value
      end

      def to_h
        @config.dup
      end
    end

    # Configuration templates
    module Templates
      def self.database_config
        {
          development: {
            adapter: 'sqlite3',
            database: 'db/development.sqlite3',
            pool: 5,
            timeout: 5000
          },
          test: {
            adapter: 'sqlite3',
            database: ':memory:',
            pool: 1,
            timeout: 5000
          },
          production: {
            adapter: 'postgresql',
            host: ENV['DB_HOST'] || 'localhost',
            database: ENV['DB_NAME'] || 'rubix_production',
            username: ENV['DB_USERNAME'],
            password: ENV['DB_PASSWORD'],
            pool: ENV['DB_POOL']&.to_i || 5,
            timeout: 5000
          }
        }
      end

      def self.server_config
        {
          development: {
            port: 3000,
            host: 'localhost',
            reload: true,
            threads: 1
          },
          test: {
            port: 3001,
            host: 'localhost',
            threads: 1
          },
          production: {
            port: ENV['PORT']&.to_i || 3000,
            host: '0.0.0.0',
            threads: ENV['SERVER_THREADS']&.to_i || 5,
            workers: ENV['SERVER_WORKERS']&.to_i || 2
          }
        }
      end

      def self.cache_config
        {
          development: {
            store: :memory,
            ttl: 300,
            compress: false
          },
          test: {
            store: :memory,
            ttl: 0,
            compress: false
          },
          production: {
            store: :redis,
            url: ENV['REDIS_URL'],
            ttl: 3600,
            compress: true,
            pool_size: 5
          }
        }
      end

      def self.session_config
        {
          development: {
            store: :memory,
            ttl: 86400,
            secure: false,
            httponly: true
          },
          test: {
            store: :memory,
            ttl: 3600,
            secure: false,
            httponly: true
          },
          production: {
            store: :redis,
            url: ENV['REDIS_URL'],
            ttl: 86400,
            secure: true,
            httponly: true,
            samesite: 'strict'
          }
        }
      end

      def self.mail_config
        {
          development: {
            delivery_method: :smtp,
            smtp: {
              host: 'localhost',
              port: 1025,
              enable_starttls_auto: false
            }
          },
          test: {
            delivery_method: :test
          },
          production: {
            delivery_method: :smtp,
            smtp: {
              host: ENV['SMTP_HOST'] || 'smtp.gmail.com',
              port: ENV['SMTP_PORT']&.to_i || 587,
              user_name: ENV['SMTP_USERNAME'],
              password: ENV['SMTP_PASSWORD'],
              enable_starttls_auto: true,
              authentication: :plain
            }
          }
        }
      end

      def self.security_config
        {
          development: {
            csrf_protection: true,
            xss_protection: true,
            hsts: false,
            secure_headers: true,
            content_security_policy: false
          },
          test: {
            csrf_protection: false,
            xss_protection: false,
            hsts: false,
            secure_headers: false,
            content_security_policy: false
          },
          production: {
            csrf_protection: true,
            xss_protection: true,
            hsts: true,
            secure_headers: true,
            content_security_policy: true,
            ssl_redirect: true
          }
        }
      end
    end
  end
end
