# Rubix Framework - A Comprehensive Ruby Web Framework
# This is the main entry point for the Rubix Framework
# Version 1.0.0
# Author: Snowbase-Studio
# Description: A full-featured Ruby framework with ORM, authentication, web server, and more

require 'rubygems'
require 'bundler/setup'
require 'yaml'
require 'json'
require 'erb'
require 'digest'
require 'securerandom'
require 'time'
require 'uri'
require 'net/http'
require 'openssl'
require 'base64'
require 'zlib'
require 'stringio'
require 'pathname'
require 'fileutils'
require 'tempfile'
require 'singleton'
require 'observer'
require 'forwardable'
require 'delegate'
require 'set'
require 'ostruct'

# Framework version and metadata
module Rubix
  VERSION = '1.0.0'
  AUTHOR = 'Snowbase-Studio'
  DESCRIPTION = 'A comprehensive Ruby web framework'

  # Framework configuration
  class Configuration
    include Singleton

    attr_accessor :database_config, :server_config, :cache_config,
                  :session_config, :security_config, :logging_config,
                  :mail_config, :asset_config, :i18n_config

    def initialize
      @database_config = {}
      @server_config = { port: 3000, host: '0.0.0.0', environment: 'development' }
      @cache_config = { store: :memory, ttl: 3600 }
      @session_config = { store: :memory, ttl: 86400, secure: true }
      @security_config = { csrf_protection: true, xss_protection: true, hsts: true }
      @logging_config = { level: :info, format: :json, file: 'logs/rubix.log' }
      @mail_config = { smtp: { host: 'localhost', port: 587 } }
      @asset_config = { compress: true, cache: true, fingerprint: true }
      @i18n_config = { default_locale: :en, fallbacks: true }
    end

    def load_from_file(path)
      config_data = YAML.load_file(path)
      config_data.each do |key, value|
        instance_variable_set("@#{key}_config", value)
      end
    end

    def to_h
      {
        database: @database_config,
        server: @server_config,
        cache: @cache_config,
        session: @session_config,
        security: @security_config,
        logging: @logging_config,
        mail: @mail_config,
        asset: @asset_config,
        i18n: @i18n_config
      }
    end
  end

  # Core application class
  class Application
    include Singleton

    attr_reader :config, :router, :database, :cache, :logger, :middleware_stack

    def initialize
      @config = Configuration.instance
      @middleware_stack = []
      @routes = {}
      @initialized = false
    end

    def configure(&block)
      @config.instance_eval(&block)
    end

    def use(middleware, *args)
      @middleware_stack << [middleware, args]
    end

    def route(method, path, controller, action)
      @routes[[method.upcase, path]] = [controller, action]
    end

    def get(path, controller, action)
      route('GET', path, controller, action)
    end

    def post(path, controller, action)
      route('POST', path, controller, action)
    end

    def put(path, controller, action)
      route('PUT', path, controller, action)
    end

    def patch(path, controller, action)
      route('PATCH', path, controller, action)
    end

    def delete(path, controller, action)
      route('DELETE', path, controller, action)
    end

    def initialize!
      return if @initialized

      # Initialize logger
      @logger = Rubix::Logging::Logger.new(@config.logging_config)

      # Initialize database
      @database = Rubix::Database::Connection.new(@config.database_config)

      # Initialize cache
      @cache = Rubix::Cache::Store.new(@config.cache_config)

      # Initialize router
      @router = Rubix::Web::Router.new(@routes)

      @initialized = true
      @logger.info("Rubix Framework initialized in #{@config.server_config[:environment]} mode")
    end

    def run!
      initialize!
      server = Rubix::Web::Server.new(@config.server_config, @middleware_stack, @router)
      server.start
    end

    def call(env)
      initialize!
      @router.call(env)
    end
  end

  # Base error classes
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class DatabaseError < Error; end
  class RoutingError < Error; end
  class AuthenticationError < Error; end
  class AuthorizationError < Error; end
  class ValidationError < Error; end

  # Utility methods available throughout the framework
  module Utils
    def self.deep_merge(hash1, hash2)
      merger = proc do |key, v1, v2|
        Hash === v1 && Hash === v2 ? v1.merge(v2, &merger) : v2
      end
      hash1.merge(hash2, &merger)
    end

    def self.deep_dup(obj)
      case obj
      when Hash
        obj.each_with_object({}) { |(k, v), h| h[k] = deep_dup(v) }
      when Array
        obj.map { |e| deep_dup(e) }
      else
        obj.dup rescue obj
      end
    end

    def self.constantize(string)
      names = string.split('::')
      names.shift if names.empty? || names.first.empty?

      constant = Object
      names.each do |name|
        constant = constant.const_defined?(name) ? constant.const_get(name) : constant.const_missing(name)
      end
      constant
    end

    def self.underscore(string)
      string.gsub(/::/, '/').
             gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').
             gsub(/([a-z\d])([A-Z])/,'\1_\2').
             tr("-", "_").
             downcase
    end

    def self.camelize(string)
      string = string.sub(/^[a-z\d]*/, &:capitalize)
      string.gsub!(/(?:_|(\/))([a-z\d]*)/i) do
        "#{Regexp.last_match(1)}#{Regexp.last_match(2).capitalize}"
      end
      string.gsub!('/', '::')
      string
    end

    def self.pluralize(word)
      return word if word.end_with?('s', 'sh', 'ch', 'x', 'z')
      return word[0..-2] + 'ies' if word.end_with?('y')
      return word + 'es' if word.end_with?('f')
      word + 's'
    end

    def self.singularize(word)
      return word[0..-4] + 'y' if word.end_with?('ies')
      return word[0..-4] if word.end_with?('ses')
      return word[0..-2] if word.end_with?('s')
      word
    end

    def self.generate_uuid
      SecureRandom.uuid
    end

    def self.generate_token(length = 32)
      SecureRandom.hex(length)
    end

    def self.hash_string(string, algorithm = 'SHA256')
      Digest.const_get(algorithm).hexdigest(string)
    end

    def self.encrypt(data, key)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = Digest::SHA256.digest(key)
      iv = cipher.random_iv
      encrypted = cipher.update(data) + cipher.final
      [encrypted, iv].map { |s| Base64.strict_encode64(s) }.join('--')
    end

    def self.decrypt(encrypted_data, key)
      encrypted, iv = encrypted_data.split('--').map { |s| Base64.strict_decode64(s) }
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.decrypt
      cipher.key = Digest::SHA256.digest(key)
      cipher.iv = iv
      cipher.update(encrypted) + cipher.final
    end

    def self.compress(data)
      Zlib::Deflate.deflate(data)
    end

    def self.decompress(data)
      Zlib::Inflate.inflate(data)
    end

    def self.safe_require(file)
      require file
    rescue LoadError
      false
    end

    def self.symbolize_keys(hash)
      hash.each_with_object({}) do |(k, v), h|
        h[k.to_sym] = case v
                      when Hash then symbolize_keys(v)
                      when Array then v.map { |e| e.is_a?(Hash) ? symbolize_keys(e) : e }
                      else v
                      end
      end
    end

    def self.stringify_keys(hash)
      hash.each_with_object({}) do |(k, v), h|
        h[k.to_s] = case v
                    when Hash then stringify_keys(v)
                    when Array then v.map { |e| e.is_a?(Hash) ? stringify_keys(e) : e }
                    else v
                    end
      end
    end
  end

  # Core Object Extensions
  class ::Object
    def blank?
      respond_to?(:empty?) ? !!empty? : !self
    end

    def present?
      !blank?
    end

    def presence
      self if present?
    end

    def try(method, *args)
      send(method, *args) if respond_to?(method)
    end

    def in?(collection)
      collection.include?(self)
    end

    def deep_dup
      Rubix::Utils.deep_dup(self)
    end
  end

  class ::Hash
    def symbolize_keys
      Rubix::Utils.symbolize_keys(self)
    end

    def stringify_keys
      Rubix::Utils.stringify_keys(self)
    end

    def deep_merge(other_hash)
      Rubix::Utils.deep_merge(self, other_hash)
    end

    def except(*keys)
      reject { |k, _| keys.include?(k) }
    end

    def slice(*keys)
      select { |k, _| keys.include?(k) }
    end

    def reverse_merge(other_hash)
      other_hash.merge(self)
    end

    def reverse_merge!(other_hash)
      merge!(other_hash)
    end
  end

  class ::Array
    def extract_options!
      if last.is_a?(Hash) && last.extractable_options?
        pop
      else
        {}
      end
    end

    def extractable_options?
      instance_of?(Hash)
    end
  end

  class ::String
    def underscore
      Rubix::Utils.underscore(self)
    end

    def camelize
      Rubix::Utils.camelize(self)
    end

    def pluralize
      Rubix::Utils.pluralize(self)
    end

    def singularize
      Rubix::Utils.singularize(self)
    end

    def constantize
      Rubix::Utils.constantize(self)
    end

    def classify
      singularize.camelize
    end

    def titleize
      split(/(\W)/).map(&:capitalize).join
    end

    def humanize
      underscore.humanize
    end

    def parameterize(sep = '-')
      downcase.gsub(/[^a-z0-9\-_]+/, sep).gsub(/-{2,}/, sep).gsub(/^#{sep}|#{sep}$/, '')
    end

    def truncate(length = 30, omission = '...')
      return self if size <= length
      slice(0, length - omission.size) + omission
    end

    def squish
      dup.squish!
    end

    def squish!
      strip!
      gsub!(/\s+/, ' ')
      self
    end

    def remove(*patterns)
      dup.remove!(*patterns)
    end

    def remove!(*patterns)
      patterns.each do |pattern|
        gsub!(pattern, '')
      end
      self
    end

    def strip_heredoc
      indent = scan(/^[ \t]*(?=\S)/).min
      indent ? gsub(/^#{indent}/, '') : self
    end
  end

  class ::Symbol
    def to_proc
      proc { |obj, *args| obj.send(self, *args) }
    end
  end

  # Core Kernel Extensions
  module Kernel
    def rubix_app
      Rubix::Application.instance
    end

    def rubix_config
      Rubix::Application.instance.config
    end

    def rubix_logger
      Rubix::Application.instance.logger
    end

    def rubix_database
      Rubix::Application.instance.database
    end

    def rubix_cache
      Rubix::Application.instance.cache
    end
  end
end

# Load all framework components
require_relative 'rubix_framework/core/base'
require_relative 'rubix_framework/core/inflector'
require_relative 'rubix_framework/core/concern'
require_relative 'rubix_framework/core/callbacks'
require_relative 'rubix_framework/core/validations'
require_relative 'rubix_framework/core/serialization'
require_relative 'rubix_framework/database/connection'
require_relative 'rubix_framework/database/model'
require_relative 'rubix_framework/database/query_builder'
require_relative 'rubix_framework/database/migrations'
require_relative 'rubix_framework/auth/user'
require_relative 'rubix_framework/auth/session'
require_relative 'rubix_framework/auth/permissions'
require_relative 'rubix_framework/web/router'
require_relative 'rubix_framework/web/controller'
require_relative 'rubix_framework/web/server'
require_relative 'rubix_framework/web/middleware'
require_relative 'rubix_framework/models/base'
require_relative 'rubix_framework/testing/test_case'
require_relative 'rubix_framework/testing/assertions'
require_relative 'rubix_framework/config/loader'
require_relative 'rubix_framework/utils/file_manager'
require_relative 'rubix_framework/utils/http_client'
require_relative 'rubix_framework/logging/logger'
require_relative 'rubix_framework/logging/formatter'
