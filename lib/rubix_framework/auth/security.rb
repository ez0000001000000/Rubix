# Advanced authentication features
# This file contains OAuth, social login, multi-factor authentication, and other advanced auth features

require 'rubygems'
require 'openssl'
require 'base64'
require 'securerandom'
require 'net/http'
require 'uri'
require 'json'

module Rubix
  module Auth
    # OAuth 2.0 implementation
    class OAuth
      def initialize(client_id, client_secret, options = {})
        @client_id = client_id
        @client_secret = client_secret
        @site = options[:site]
        @authorize_url = options[:authorize_url] || '/oauth/authorize'
        @token_url = options[:token_url] || '/oauth/token'
        @scope = options[:scope] || 'read'
        @redirect_uri = options[:redirect_uri]
      end

      def authorize_url(state = nil)
        params = {
          client_id: @client_id,
          redirect_uri: @redirect_uri,
          scope: @scope,
          response_type: 'code',
          state: state
        }

        "#{@site}#{@authorize_url}?#{URI.encode_www_form(params)}"
      end

      def get_token(code, options = {})
        params = {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: @redirect_uri,
          client_id: @client_id,
          client_secret: @client_secret
        }

        response = post_request(@token_url, params)
        parse_token_response(response)
      end

      def refresh_token(refresh_token)
        params = {
          grant_type: 'refresh_token',
          refresh_token: refresh_token,
          client_id: @client_id,
          client_secret: @client_secret
        }

        response = post_request(@token_url, params)
        parse_token_response(response)
      end

      private

      def post_request(path, params)
        uri = URI("#{@site}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'

        request = Net::HTTP::Post.new(uri)
        request.set_form_data(params)
        request['Accept'] = 'application/json'

        response = http.request(request)
        JSON.parse(response.body)
      end

      def parse_token_response(response)
        if response['error']
          raise OAuthError.new(response['error'], response['error_description'])
        else
          Token.new(
            access_token: response['access_token'],
            refresh_token: response['refresh_token'],
            expires_at: response['expires_in'] ? Time.now + response['expires_in'] : nil,
            token_type: response['token_type'] || 'Bearer'
          )
        end
      end

      class Token
        attr_accessor :access_token, :refresh_token, :expires_at, :token_type

        def initialize(attributes = {})
          @access_token = attributes[:access_token]
          @refresh_token = attributes[:refresh_token]
          @expires_at = attributes[:expires_at]
          @token_type = attributes[:token_type] || 'Bearer'
        end

        def expired?
          @expires_at && Time.now >= @expires_at
        end

        def to_hash
          {
            access_token: @access_token,
            refresh_token: @refresh_token,
            expires_at: @expires_at,
            token_type: @token_type
          }
        end
      end

      class OAuthError < StandardError
        attr_reader :error, :description

        def initialize(error, description = nil)
          @error = error
          @description = description
          super("#{error}: #{description}")
        end
      end
    end

    # Social authentication providers
    class OmniAuth
      PROVIDERS = {
        google: {
          name: 'Google',
          authorize_url: 'https://accounts.google.com/o/oauth2/auth',
          token_url: 'https://oauth2.googleapis.com/token',
          user_info_url: 'https://www.googleapis.com/oauth2/v2/userinfo',
          scope: 'openid email profile'
        },
        github: {
          name: 'GitHub',
          authorize_url: 'https://github.com/login/oauth/authorize',
          token_url: 'https://github.com/login/oauth/access_token',
          user_info_url: 'https://api.github.com/user',
          scope: 'user:email'
        },
        facebook: {
          name: 'Facebook',
          authorize_url: 'https://www.facebook.com/v3.2/dialog/oauth',
          token_url: 'https://graph.facebook.com/v3.2/oauth/access_token',
          user_info_url: 'https://graph.facebook.com/me?fields=id,name,email,picture',
          scope: 'email,public_profile'
        },
        twitter: {
          name: 'Twitter',
          authorize_url: 'https://api.twitter.com/oauth/authenticate',
          token_url: 'https://api.twitter.com/oauth/access_token',
          user_info_url: 'https://api.twitter.com/1.1/account/verify_credentials.json',
          scope: 'read'
        }
      }

      def initialize(provider, client_id, client_secret, options = {})
        @provider = provider.to_sym
        @client_id = client_id
        @client_secret = client_secret
        @options = PROVIDERS[@provider].merge(options)
        @oauth = OAuth.new(client_id, client_secret, @options)
      end

      def authorize_url(state = nil)
        @oauth.authorize_url(state)
      end

      def authenticate(code)
        token = @oauth.get_token(code)
        user_info = fetch_user_info(token)
        create_or_update_user(user_info, @provider)
      end

      private

      def fetch_user_info(token)
        uri = URI(@options[:user_info_url])
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        request = Net::HTTP::Get.new(uri)
        request['Authorization'] = "#{token.token_type} #{token.access_token}"
        request['Accept'] = 'application/json'

        response = http.request(request)
        JSON.parse(response.body)
      end

      def create_or_update_user(user_info, provider)
        # This would integrate with your User model
        # For now, return a hash representation
        {
          provider: provider,
          uid: user_info['id'] || user_info['sub'],
          name: user_info['name'] || user_info['login'],
          email: user_info['email'],
          avatar_url: user_info['picture'] || user_info['avatar_url'],
          raw_info: user_info
        }
      end
    end

    # Multi-factor authentication
    class MFA
      def initialize(user)
        @user = user
        @secret = load_or_generate_secret
      end

      def enabled?
        !@secret.nil?
      end

      def provisioning_uri
        return nil unless enabled?

        require 'rotp'
        totp = ROTP::TOTP.new(@secret, issuer: 'Rubix Framework')
        totp.provisioning_uri(@user.email)
      rescue LoadError
        nil
      end

      def verify(code)
        return false unless enabled?

        require 'rotp'
        totp = ROTP::TOTP.new(@secret)
        totp.verify(code, drift_behind: 30)
      rescue LoadError
        false
      end

      def enable(code)
        return false unless verify(code)

        @user.update(mfa_enabled: true, mfa_secret: @secret)
        true
      end

      def disable
        @user.update(mfa_enabled: false, mfa_secret: nil)
        @secret = nil
        true
      end

      def backup_codes
        return [] unless enabled?

        # Generate backup codes
        codes = []
        10.times { codes << SecureRandom.hex(4).upcase }
        @user.update(mfa_backup_codes: codes.to_json)
        codes
      end

      def verify_backup_code(code)
        return false unless @user.mfa_backup_codes

        codes = JSON.parse(@user.mfa_backup_codes)
        if codes.include?(code)
          codes.delete(code)
          @user.update(mfa_backup_codes: codes.to_json)
          true
        else
          false
        end
      end

      private

      def load_or_generate_secret
        if @user.mfa_secret
          @user.mfa_secret
        else
          ROTP::Base32.random
        end
      rescue LoadError
        nil
      end
    end

    # Passwordless authentication
    class PasswordlessAuth
      def initialize(options = {})
        @token_expiry = options[:token_expiry] || 900 # 15 minutes
        @email_sender = options[:email_sender]
      end

      def send_magic_link(email, redirect_url = nil)
        user = find_user_by_email(email)
        return false unless user

        token = generate_token
        store_token(token, user.id, redirect_url)
        send_email(user, token, redirect_url)
        true
      end

      def authenticate(token)
        record = find_token_record(token)
        return false unless record && !expired?(record)

        user = find_user_by_id(record['user_id'])
        delete_token(token)

        if user
          session_data = { user_id: user.id, authenticated_at: Time.now }
          session_data[:redirect_url] = record['redirect_url'] if record['redirect_url']
          session_data
        else
          false
        end
      end

      private

      def generate_token
        SecureRandom.urlsafe_base64(32)
      end

      def store_token(token, user_id, redirect_url)
        # Store token in database/cache
        # This is a simplified implementation
        @tokens ||= {}
        @tokens[token] = {
          user_id: user_id,
          redirect_url: redirect_url,
          created_at: Time.now
        }
      end

      def find_token_record(token)
        @tokens[token] if @tokens
      end

      def delete_token(token)
        @tokens.delete(token) if @tokens
      end

      def expired?(record)
        Time.now - record['created_at'] > @token_expiry
      end

      def find_user_by_email(email)
        # This would query your User model
        User.find_by(email: email)
      end

      def find_user_by_id(id)
        # This would query your User model
        User.find(id)
      end

      def send_email(user, token, redirect_url)
        return unless @email_sender

        magic_link = build_magic_link(token, redirect_url)

        @email_sender.send(
          to: user.email,
          subject: 'Your magic login link',
          body: "Click here to log in: #{magic_link}"
        )
      end

      def build_magic_link(token, redirect_url)
        base_url = ENV['APP_URL'] || 'http://localhost:3000'
        url = "#{base_url}/auth/magic_link?token=#{token}"
        url << "&redirect_url=#{URI.encode_www_form_component(redirect_url)}" if redirect_url
        url
      end
    end

    # Role-based access control (RBAC)
    class RBAC
      def initialize
        @roles = {}
        @permissions = {}
        @role_permissions = {}
        load_default_permissions
      end

      def define_role(name, permissions = [])
        @roles[name] = { permissions: permissions }
        @role_permissions[name] = permissions
      end

      def assign_role(user, role_name)
        user.roles ||= []
        user.roles << role_name unless user.roles.include?(role_name)
        user.save
      end

      def revoke_role(user, role_name)
        user.roles&.delete(role_name)
        user.save
      end

      def has_role?(user, role_name)
        user.roles&.include?(role_name)
      end

      def can?(user, permission)
        return true if user.roles&.include?('admin')

        user.roles&.any? do |role|
          @role_permissions[role]&.include?(permission)
        end
      end

      def define_permission(name, description = '')
        @permissions[name] = description
      end

      def permissions_for_role(role_name)
        @role_permissions[role_name] || []
      end

      def roles_for_user(user)
        user.roles || []
      end

      def add_permission_to_role(role_name, permission)
        @role_permissions[role_name] ||= []
        @role_permissions[role_name] << permission unless @role_permissions[role_name].include?(permission)
      end

      def remove_permission_from_role(role_name, permission)
        @role_permissions[role_name]&.delete(permission)
      end

      private

      def load_default_permissions
        define_permission('users.read', 'Read user information')
        define_permission('users.write', 'Create and update users')
        define_permission('users.delete', 'Delete users')
        define_permission('posts.read', 'Read posts')
        define_permission('posts.write', 'Create and update posts')
        define_permission('posts.delete', 'Delete posts')
        define_permission('comments.read', 'Read comments')
        define_permission('comments.write', 'Create and update comments')
        define_permission('comments.delete', 'Delete comments')

        define_role('user', ['users.read', 'posts.read', 'posts.write', 'comments.read', 'comments.write'])
        define_role('moderator', ['users.read', 'posts.read', 'posts.write', 'posts.delete', 'comments.read', 'comments.write', 'comments.delete'])
        define_role('admin', ['users.read', 'users.write', 'users.delete', 'posts.read', 'posts.write', 'posts.delete', 'comments.read', 'comments.write', 'comments.delete'])
      end
    end

    # Session management with advanced features
    class AdvancedSession
      def initialize(store = nil)
        @store = store || MemorySessionStore.new
        @cookie_name = '_rubix_session'
        @cookie_options = {
          path: '/',
          httponly: true,
          secure: ENV['RACK_ENV'] == 'production',
          same_site: :lax
        }
      end

      def create(env, user_id, options = {})
        session_id = generate_session_id
        session_data = {
          user_id: user_id,
          created_at: Time.now,
          expires_at: options[:expires_at] || default_expiry,
          ip_address: env['REMOTE_ADDR'],
          user_agent: env['HTTP_USER_AGENT'],
          data: options[:data] || {}
        }

        @store.set(session_id, session_data)
        set_session_cookie(env, session_id)
        session_id
      end

      def find(env)
        session_id = get_session_id_from_cookie(env)
        return nil unless session_id

        session_data = @store.get(session_id)
        return nil unless session_data && !expired?(session_data)

        update_activity(session_id, session_data)
        session_data
      end

      def destroy(env)
        session_id = get_session_id_from_cookie(env)
        return unless session_id

        @store.delete(session_id)
        delete_session_cookie(env)
      end

      def renew(env)
        session_data = find(env)
        return unless session_data

        session_data['expires_at'] = default_expiry
        session_id = get_session_id_from_cookie(env)
        @store.set(session_id, session_data)
      end

      def cleanup_expired
        # This would be called periodically to clean up expired sessions
        @store.cleanup_expired
      end

      def active_sessions_count
        @store.count
      end

      private

      def generate_session_id
        SecureRandom.hex(32)
      end

      def default_expiry
        Time.now + (30 * 24 * 60 * 60) # 30 days
      end

      def expired?(session_data)
        Time.now > Time.parse(session_data['expires_at'])
      end

      def update_activity(session_id, session_data)
        session_data['last_activity'] = Time.now
        @store.set(session_id, session_data)
      end

      def get_session_id_from_cookie(env)
        cookie_header = env['HTTP_COOKIE']
        return nil unless cookie_header

        cookies = parse_cookies(cookie_header)
        cookies[@cookie_name]
      end

      def set_session_cookie(env, session_id)
        cookie_value = build_cookie_value(session_id)
        env['rubix.session.cookie'] = cookie_value
      end

      def delete_session_cookie(env)
        expired_cookie = build_cookie_value('', Time.at(0))
        env['rubix.session.cookie'] = expired_cookie
      end

      def build_cookie_value(value, expires = nil)
        cookie_parts = ["#{@cookie_name}=#{value}"]
        options = @cookie_options.dup
        options[:expires] = expires.httpdate if expires
        options[:max_age] = nil if expires&.past?

        options.each do |key, val|
          next unless val
          cookie_parts << "#{key}=#{val}"
        end

        cookie_parts.join('; ')
      end

      def parse_cookies(cookie_header)
        cookies = {}
        cookie_header.split(';').each do |cookie|
          name, value = cookie.strip.split('=', 2)
          cookies[name] = value if name && value
        end
        cookies
      end

      class MemorySessionStore
        def initialize
          @sessions = {}
          @mutex = Mutex.new
        end

        def get(session_id)
          @mutex.synchronize { @sessions[session_id] }
        end

        def set(session_id, data)
          @mutex.synchronize { @sessions[session_id] = data }
        end

        def delete(session_id)
          @mutex.synchronize { @sessions.delete(session_id) }
        end

        def cleanup_expired
          @mutex.synchronize do
            @sessions.delete_if do |_, data|
              Time.now > Time.parse(data['expires_at'])
            end
          end
        end

        def count
          @mutex.synchronize { @sessions.size }
        end
      end
    end

    # API token management
    class APITokens
      def initialize(user_model = User)
        @user_model = user_model
        @token_length = 32
        @token_prefix = 'rbt_'
      end

      def create(user, options = {})
        token_value = generate_token
        token_record = {
          token: "#{@token_prefix}#{token_value}",
          user_id: user.id,
          name: options[:name] || 'API Token',
          scopes: options[:scopes] || ['read'],
          expires_at: options[:expires_at],
          created_at: Time.now,
          last_used_at: nil,
          revoked: false
        }

        # Store token record (this would be in your database)
        store_token_record(token_record)

        token_record
      end

      def authenticate(token_string)
        return nil unless token_string&.start_with?(@token_prefix)

        token_value = token_string.sub(@token_prefix, '')
        token_record = find_token_record(token_value)

        return nil unless token_record && !expired?(token_record) && !revoked?(token_record)

        update_last_used(token_record)
        @user_model.find(token_record['user_id'])
      end

      def revoke(token_string)
        token_value = token_string.sub(@token_prefix, '')
        token_record = find_token_record(token_value)

        if token_record
          token_record['revoked'] = true
          update_token_record(token_record)
          true
        else
          false
        end
      end

      def list(user)
        find_tokens_for_user(user.id)
      end

      def scopes_allowed?(token_record, required_scopes)
        token_scopes = token_record['scopes'] || []
        required_scopes.all? { |scope| token_scopes.include?(scope) }
      end

      private

      def generate_token
        SecureRandom.urlsafe_base64(@token_length)
      end

      def store_token_record(record)
        # This would store the token in your database
        @tokens ||= {}
        @tokens[record[:token].sub(@token_prefix, '')] = record
      end

      def find_token_record(token_value)
        @tokens[token_value] if @tokens
      end

      def find_tokens_for_user(user_id)
        return [] unless @tokens

        @tokens.values.select { |token| token['user_id'] == user_id && !revoked?(token) }
      end

      def expired?(token_record)
        expires_at = token_record['expires_at']
        expires_at && Time.now > Time.parse(expires_at)
      end

      def revoked?(token_record)
        token_record['revoked']
      end

      def update_last_used(token_record)
        token_record['last_used_at'] = Time.now
        update_token_record(token_record)
      end

      def update_token_record(record)
        # Update the token record in storage
        token_value = record[:token].sub(@token_prefix, '')
        @tokens[token_value] = record if @tokens
      end
    end

    # Security audit logging
    class SecurityAudit
      def initialize(logger = nil)
        @logger = logger || Logger.new(STDOUT)
        @events = []
      end

      def log_login_success(user, ip_address, user_agent)
        log_event('login_success', user: user.id, ip: ip_address, user_agent: user_agent)
      end

      def log_login_failure(email, ip_address, user_agent, reason = nil)
        log_event('login_failure', email: email, ip: ip_address, user_agent: user_agent, reason: reason)
      end

      def log_password_change(user, ip_address)
        log_event('password_change', user: user.id, ip: ip_address)
      end

      def log_password_reset_request(email, ip_address)
        log_event('password_reset_request', email: email, ip: ip_address)
      end

      def log_suspicious_activity(user, activity, ip_address, details = {})
        log_event('suspicious_activity', user: user&.id, activity: activity, ip: ip_address, details: details)
      end

      def log_api_access(user, endpoint, method, ip_address, response_status)
        log_event('api_access', user: user&.id, endpoint: endpoint, method: method, ip: ip_address, status: response_status)
      end

      def log_permission_denied(user, resource, action, ip_address)
        log_event('permission_denied', user: user&.id, resource: resource, action: action, ip: ip_address)
      end

      def get_events(filters = {})
        events = @events

        if filters[:user_id]
          events = events.select { |e| e[:user_id] == filters[:user_id] }
        end

        if filters[:event_type]
          events = events.select { |e| e[:event_type] == filters[:event_type] }
        end

        if filters[:since]
          events = events.select { |e| e[:timestamp] >= filters[:since] }
        end

        if filters[:until]
          events = events.select { |e| e[:timestamp] <= filters[:until] }
        end

        events
      end

      def export_events(format = :json)
        case format
        when :json
          @events.to_json
        when :csv
          # Convert to CSV format
          csv_data = "timestamp,event_type,user_id,ip_address,details\n"
          @events.each do |event|
            csv_data << "#{event[:timestamp]},#{event[:event_type]},#{event[:user_id]},#{event[:ip]},#{event[:details].to_json}\n"
          end
          csv_data
        else
          @events.inspect
        end
      end

      private

      def log_event(event_type, data = {})
        event = {
          timestamp: Time.now,
          event_type: event_type,
          user_id: data[:user] || data[:user_id],
          ip_address: data[:ip],
          user_agent: data[:user_agent],
          details: data.except(:user, :user_id, :ip, :user_agent)
        }

        @events << event
        @logger.info("SECURITY AUDIT: #{event_type} - User: #{event[:user_id]} - IP: #{event[:ip_address]} - Details: #{event[:details]}")
      end
    end

    # Brute force protection
    class BruteForceProtection
      def initialize(options = {})
        @max_attempts = options[:max_attempts] || 5
        @lockout_duration = options[:lockout_duration] || 900 # 15 minutes
        @attempts = {}
        @locked_accounts = {}
      end

      def record_failed_attempt(identifier)
        @attempts[identifier] ||= []
        @attempts[identifier] << Time.now

        # Clean old attempts
        @attempts[identifier].select! { |time| Time.now - time < @lockout_duration }

        if @attempts[identifier].size >= @max_attempts
          lock_account(identifier)
          return true # Account is now locked
        end

        false
      end

      def record_successful_attempt(identifier)
        @attempts.delete(identifier)
        @locked_accounts.delete(identifier)
      end

      def account_locked?(identifier)
        return false unless @locked_accounts[identifier]

        lock_time = @locked_accounts[identifier]
        if Time.now - lock_time > @lockout_duration
          @locked_accounts.delete(identifier)
          false
        else
          true
        end
      end

      def time_until_unlock(identifier)
        return 0 unless account_locked?(identifier)

        lock_time = @locked_accounts[identifier]
        remaining = @lockout_duration - (Time.now - lock_time)
        [remaining, 0].max
      end

      def reset(identifier)
        @attempts.delete(identifier)
        @locked_accounts.delete(identifier)
      end

      private

      def lock_account(identifier)
        @locked_accounts[identifier] = Time.now
        @attempts.delete(identifier) # Clear attempts after locking
      end
    end
  end
end
