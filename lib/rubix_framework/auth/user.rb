# Authentication and authorization system
# This file contains user management, sessions, and permissions

module Rubix
  module Auth
    # User model with authentication
    class User < Rubix::Database::Model
      column :email, :string, null: false, unique: true
      column :password_digest, :string, null: false
      column :first_name, :string
      column :last_name, :string
      column :role, :string, default: 'user'
      column :confirmed_at, :datetime
      column :reset_password_token, :string
      column :reset_password_sent_at, :datetime
      column :remember_created_at, :datetime
      column :sign_in_count, :integer, default: 0
      column :current_sign_in_at, :datetime
      column :last_sign_in_at, :datetime
      column :current_sign_in_ip, :string
      column :last_sign_in_ip, :string
      column :failed_attempts, :integer, default: 0
      column :unlock_token, :string
      column :locked_at, :datetime
      timestamps

      validates_presence_of :email, :password_digest
      validates_format_of :email, with: /\A[^@\s]+@[^@\s]+\z/
      validates_uniqueness_of :email
      validates_length_of :password_digest, minimum: 60

      attr_accessor :password, :password_confirmation, :remember_me

      before_save :encrypt_password
      before_create :generate_confirmation_token

      def self.authenticate(email, password)
        user = find_by(email: email&.downcase&.strip)
        return nil unless user

        if user.valid_password?(password)
          user.update_sign_in_info!
          user
        else
          user.increment_failed_attempts!
          nil
        end
      end

      def self.find_by_email(email)
        find_by(email: email&.downcase&.strip)
      end

      def self.confirm_by_token(token)
        user = find_by(confirmation_token: token)
        return nil unless user

        user.confirm!
        user
      end

      def self.send_reset_password_instructions(email)
        user = find_by_email(email)
        return false unless user

        user.generate_reset_password_token!
        # Send email here
        true
      end

      def self.reset_password_by_token(token, password, password_confirmation)
        user = find_by(reset_password_token: token)
        return nil unless user&.reset_password_period_valid?

        user.reset_password!(password, password_confirmation)
        user
      end

      def valid_password?(password)
        return false if password_digest.blank?

        begin
          BCrypt::Password.new(password_digest).is_password?(password)
        rescue BCrypt::Errors::InvalidHash
          false
        end
      end

      def password=(new_password)
        @password = new_password
        self.password_digest = encrypt(new_password) if new_password.present?
      end

      def confirm!
        update(confirmed_at: Time.now, confirmation_token: nil)
      end

      def confirmed?
        confirmed_at.present?
      end

      def generate_confirmation_token
        self.confirmation_token = Rubix::Utils.generate_token
      end

      def generate_reset_password_token!
        self.reset_password_token = Rubix::Utils.generate_token
        self.reset_password_sent_at = Time.now
        save
      end

      def reset_password_period_valid?
        reset_password_sent_at && reset_password_sent_at > 2.hours.ago
      end

      def reset_password!(password, password_confirmation)
        self.password = password
        self.password_confirmation = password_confirmation

        if valid?
          self.reset_password_token = nil
          self.reset_password_sent_at = nil
          save
        else
          false
        end
      end

      def remember_me!
        self.remember_token = Rubix::Utils.generate_token
        self.remember_created_at = Time.now
        save(validate: false)
      end

      def forget_me!
        update(remember_token: nil, remember_created_at: nil)
      end

      def remember_me?
        remember_token.present? && remember_created_at.present?
      end

      def update_sign_in_info!(ip = nil)
        now = Time.now
        update(
          sign_in_count: sign_in_count + 1,
          current_sign_in_at: now,
          last_sign_in_at: current_sign_in_at,
          current_sign_in_ip: ip,
          last_sign_in_ip: current_sign_in_ip,
          failed_attempts: 0,
          unlock_token: nil,
          locked_at: nil
        )
      end

      def increment_failed_attempts!
        update(failed_attempts: failed_attempts + 1)
        lock_access! if failed_attempts >= 5
      end

      def lock_access!
        update(locked_at: Time.now, unlock_token: Rubix::Utils.generate_token)
      end

      def unlock_access!
        update(locked_at: nil, unlock_token: nil, failed_attempts: 0)
      end

      def access_locked?
        locked_at.present? && lock_expired?
      end

      def lock_expired?
        locked_at && locked_at < 1.hour.ago
      end

      def admin?
        role == 'admin'
      end

      def moderator?
        role == 'moderator'
      end

      def user?
        role == 'user'
      end

      def full_name
        [first_name, last_name].compact.join(' ')
      end

      def display_name
        full_name.presence || email.split('@').first
      end

      private

      def encrypt_password
        if password.present?
          self.password_digest = encrypt(password)
        end
      end

      def encrypt(password)
        cost = BCrypt::Engine::DEFAULT_COST
        BCrypt::Password.create(password, cost: cost)
      end

      def generate_confirmation_token
        self.confirmation_token = Rubix::Utils.generate_token unless confirmed?
      end
    end

    # Session management
    class Session
      attr_reader :session_id, :data, :expires_at

      def initialize(session_id = nil, data = {})
        @session_id = session_id || Rubix::Utils.generate_token
        @data = data.symbolize_keys
        @expires_at = Time.now + 24.hours
      end

      def [](key)
        @data[key.to_sym]
      end

      def []=(key, value)
        @data[key.to_sym] = value
      end

      def delete(key)
        @data.delete(key.to_sym)
      end

      def clear
        @data.clear
      end

      def empty?
        @data.empty?
      end

      def keys
        @data.keys
      end

      def values
        @data.values
      end

      def to_hash
        @data.dup
      end

      def expired?
        Time.now > @expires_at
      end

      def renew!(duration = 24.hours)
        @expires_at = Time.now + duration
      end

      def destroy!
        clear
        @expires_at = Time.now
      end

      def user
        return nil unless self[:user_id]
        @user ||= Rubix::Auth::User.find(self[:user_id])
      rescue Rubix::Database::RecordNotFound
        nil
      end

      def user=(user)
        if user
          self[:user_id] = user.id
          @user = user
        else
          delete(:user_id)
          @user = nil
        end
      end

      def authenticated?
        user.present?
      end

      def to_json(*args)
        {
          session_id: @session_id,
          data: @data,
          expires_at: @expires_at
        }.to_json(*args)
      end

      def self.from_json(json_string)
        data = JSON.parse(json_string, symbolize_names: true)
        new(data[:session_id], data[:data]).tap do |session|
          session.instance_variable_set(:@expires_at, Time.parse(data[:expires_at]))
        end
      end
    end

    # Session store interface
    class SessionStore
      def find(session_id)
        raise NotImplementedError
      end

      def create(session)
        raise NotImplementedError
      end

      def update(session)
        raise NotImplementedError
      end

      def destroy(session_id)
        raise NotImplementedError
      end

      def cleanup_expired
        raise NotImplementedError
      end
    end

    # Memory-based session store
    class MemorySessionStore < SessionStore
      def initialize
        @sessions = {}
        @mutex = Mutex.new
      end

      def find(session_id)
        @mutex.synchronize do
          session_data = @sessions[session_id]
          return nil unless session_data

          session = Session.from_json(session_data)
          return nil if session.expired?

          session
        end
      end

      def create(session)
        @mutex.synchronize do
          @sessions[session.session_id] = session.to_json
          session
        end
      end

      def update(session)
        create(session)
      end

      def destroy(session_id)
        @mutex.synchronize do
          @sessions.delete(session_id)
        end
      end

      def cleanup_expired
        @mutex.synchronize do
          @sessions.reject! do |session_id, session_data|
            Session.from_json(session_data).expired?
          end
        end
      end
    end

    # File-based session store
    class FileSessionStore < SessionStore
      def initialize(path = 'tmp/sessions')
        @path = path
        FileUtils.mkdir_p(@path)
      end

      def find(session_id)
        file_path = session_file_path(session_id)
        return nil unless File.exist?(file_path)

        session_data = File.read(file_path)
        session = Session.from_json(session_data)

        if session.expired?
          destroy(session_id)
          nil
        else
          session
        end
      rescue JSON::ParserError
        nil
      end

      def create(session)
        file_path = session_file_path(session.session_id)
        File.write(file_path, session.to_json)
        session
      end

      def update(session)
        create(session)
      end

      def destroy(session_id)
        file_path = session_file_path(session_id)
        File.delete(file_path) if File.exist?(file_path)
      end

      def cleanup_expired
        Dir.glob(File.join(@path, '*.session')).each do |file|
          session_id = File.basename(file, '.session')
          find(session_id) # This will delete expired sessions
        end
      end

      private

      def session_file_path(session_id)
        File.join(@path, "#{session_id}.session")
      end
    end

    # Database-backed session store
    class DatabaseSessionStore < SessionStore
      def initialize(table_name = 'sessions')
        @table_name = table_name
        create_table
      end

      def find(session_id)
        result = connection.execute(
          "SELECT data, expires_at FROM #{@table_name} WHERE session_id = ? AND expires_at > ?",
          [session_id, Time.now.to_i]
        ).first

        return nil unless result

        session_data = JSON.parse(result['data'], symbolize_names: true)
        session = Session.new(session_id, session_data)
        session.instance_variable_set(:@expires_at, Time.at(result['expires_at']))
        session
      rescue JSON::ParserError
        nil
      end

      def create(session)
        connection.execute(
          "INSERT OR REPLACE INTO #{@table_name} (session_id, data, expires_at) VALUES (?, ?, ?)",
          [session.session_id, session.to_json, session.expires_at.to_i]
        )
        session
      end

      def update(session)
        create(session)
      end

      def destroy(session_id)
        connection.execute("DELETE FROM #{@table_name} WHERE session_id = ?", [session_id])
      end

      def cleanup_expired
        connection.execute("DELETE FROM #{@table_name} WHERE expires_at <= ?", [Time.now.to_i])
      end

      private

      def connection
        Rubix::Application.instance.database
      end

      def create_table
        connection.execute(<<-SQL)
          CREATE TABLE IF NOT EXISTS #{@table_name} (
            session_id TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            expires_at INTEGER NOT NULL
          )
        SQL
      end
    end

    # Session manager
    class SessionManager
      attr_reader :store

      def initialize(store_type = :memory, options = {})
        @store = case store_type
                 when :memory
                   MemorySessionStore.new
                 when :file
                   FileSessionStore.new(options[:path])
                 when :database
                   DatabaseSessionStore.new(options[:table_name])
                 else
                   raise ConfigurationError, "Unknown session store type: #{store_type}"
                 end
      end

      def find(session_id)
        @store.find(session_id)
      end

      def create(data = {})
        session = Session.new(nil, data)
        @store.create(session)
      end

      def update(session)
        @store.update(session)
      end

      def destroy(session_id)
        @store.destroy(session_id)
      end

      def cleanup_expired
        @store.cleanup_expired
      end
    end

    # Permission system
    module Permissions
      # Role-based access control
      class Role
        attr_reader :name, :permissions

        def initialize(name, permissions = [])
          @name = name
          @permissions = permissions
        end

        def can?(permission)
          @permissions.include?(permission)
        end

        def add_permission(permission)
          @permissions << permission unless @permissions.include?(permission)
        end

        def remove_permission(permission)
          @permissions.delete(permission)
        end

        def has_all_permissions?(*permissions)
          permissions.all? { |p| can?(p) }
        end

        def has_any_permission?(*permissions)
          permissions.any? { |p| can?(p) }
        end
      end

      # Permission definition DSL
      class PermissionDSL
        def initialize
          @permissions = {}
          @roles = {}
        end

        def permission(name, description = nil)
          @permissions[name] = description
        end

        def role(name, &block)
          role_permissions = []
          dsl = RoleDSL.new(role_permissions)
          dsl.instance_eval(&block)
          @roles[name] = Role.new(name, role_permissions)
        end

        def permissions
          @permissions
        end

        def roles
          @roles
        end

        class RoleDSL
          def initialize(permissions)
            @permissions = permissions
          end

          def can(*permissions)
            @permissions.concat(permissions)
          end
        end
      end

      # Permission manager
      class Manager
        attr_reader :permissions, :roles

        def initialize
          @permissions = {}
          @roles = {}
          @user_roles = {}
        end

        def define_permissions(&block)
          dsl = PermissionDSL.new
          dsl.instance_eval(&block)

          @permissions.merge!(dsl.permissions)
          @roles.merge!(dsl.roles)
        end

        def assign_role(user_id, role_name)
          @user_roles[user_id] ||= []
          @user_roles[user_id] << role_name unless @user_roles[user_id].include?(role_name)
        end

        def remove_role(user_id, role_name)
          @user_roles[user_id]&.delete(role_name)
        end

        def user_roles(user_id)
          @user_roles[user_id] || []
        end

        def user_permissions(user_id)
          user_roles(user_id).flat_map do |role_name|
            @roles[role_name]&.permissions || []
          end.uniq
        end

        def can?(user_id, permission)
          user_permissions(user_id).include?(permission)
        end

        def authorize!(user_id, permission)
          unless can?(user_id, permission)
            raise AuthorizationError, "User #{user_id} is not authorized to #{permission}"
          end
        end

        def role_exists?(role_name)
          @roles.key?(role_name)
        end

        def permission_exists?(permission)
          @permissions.key?(permission)
        end

        def add_role(name, permissions = [])
          @roles[name] = Role.new(name, permissions)
        end

        def add_permission(name, description = nil)
          @permissions[name] = description
        end
      end

      # Authorization middleware
      class AuthorizationMiddleware
        def initialize(app, permission_manager)
          @app = app
          @permission_manager = permission_manager
        end

        def call(env)
          request = Rack::Request.new(env)

          # Extract user_id from session or JWT
          user_id = extract_user_id(request)

          # Check permissions for the current route
          if requires_authorization?(request)
            permission = required_permission(request)
            @permission_manager.authorize!(user_id, permission) if permission
          end

          @app.call(env)
        end

        private

        def extract_user_id(request)
          # Extract from session or JWT token
          session = request.session
          session['user_id'] if session
        end

        def requires_authorization?(request)
          # Check if the route requires authorization
          true # Simplified
        end

        def required_permission(request)
          # Determine required permission based on route
          case request.path
          when /^\/admin/
            :manage_users
          when /^\/api\/users/
            :read_users
          else
            nil
          end
        end
      end
    end

    # Authentication middleware
    class AuthenticationMiddleware
      def initialize(app, session_manager)
        @app = app
        @session_manager = session_manager
      end

      def call(env)
        request = Rack::Request.new(env)

        # Extract session_id from cookies or headers
        session_id = extract_session_id(request)

        if session_id
          session = @session_manager.find(session_id)
          env['rack.session'] = session if session
        end

        status, headers, body = @app.call(env)

        # Update session cookie if session exists
        if env['rack.session']
          session = env['rack.session']
          @session_manager.update(session)

          cookie_options = {
            value: session.session_id,
            expires: session.expires_at,
            path: '/',
            httponly: true,
            secure: request.ssl?
          }

          Rack::Utils.set_cookie_header!(headers, 'session_id', cookie_options)
        end

        [status, headers, body]
      end

      private

      def extract_session_id(request)
        request.cookies['session_id'] || request.env['HTTP_X_SESSION_ID']
      end
    end

    # Password utilities
    module Password
      def self.hash(password, cost = BCrypt::Engine::DEFAULT_COST)
        BCrypt::Password.create(password, cost: cost)
      end

      def self.verify(password, hash)
        BCrypt::Password.new(hash).is_password?(password)
      rescue BCrypt::Errors::InvalidHash
        false
      end

      def self.secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        l = a.unpack("C*")
        r = b.unpack("C*")
        result = 0

        l.zip(r) { |x, y| result |= x ^ y }

        result.zero?
      end

      def self.generate_token(length = 32)
        Rubix::Utils.generate_token(length)
      end

      def self.generate_password_reset_token
        generate_token(64)
      end

      def self.generate_confirmation_token
        generate_token(64)
      end
    end

    # JWT utilities for stateless authentication
    module JWT
      def self.encode(payload, secret = nil, algorithm = 'HS256')
        secret ||= Rubix::Application.instance.config.security_config[:jwt_secret]
        JWT.encode(payload, secret, algorithm)
      end

      def self.decode(token, secret = nil, algorithm = 'HS256', verify = true)
        secret ||= Rubix::Application.instance.config.security_config[:jwt_secret]
        JWT.decode(token, secret, verify, algorithm: algorithm)
      rescue JWT::DecodeError
        nil
      end

      def self.valid?(token, secret = nil)
        decode(token, secret).present?
      end

      def self.payload(token, secret = nil)
        decoded = decode(token, secret)
        decoded.first if decoded
      end

      def self.user_from_token(token, secret = nil)
        payload = payload(token, secret)
        return nil unless payload

        user_id = payload['user_id'] || payload[:user_id]
        Rubix::Auth::User.find(user_id) if user_id
      rescue Rubix::Database::RecordNotFound
        nil
      end
    end

    # OmniAuth integration (simplified)
    module OmniAuth
      class Strategy
        attr_reader :name, :options

        def initialize(name, options = {})
          @name = name
          @options = options
        end

        def authenticate(request)
          # Implementation for each strategy
          raise NotImplementedError
        end

        def callback(request)
          # Implementation for callback handling
          raise NotImplementedError
        end
      end

      class GoogleStrategy < Strategy
        def initialize(options = {})
          super(:google, options)
        end

        def authenticate(request)
          # Redirect to Google OAuth
          redirect_url = build_auth_url(request)
          [302, { 'Location' => redirect_url }, []]
        end

        def callback(request)
          # Handle Google OAuth callback
          code = request.params['code']
          # Exchange code for access token and user info
          user_info = exchange_code_for_user_info(code)
          create_or_update_user(user_info)
        end

        private

        def build_auth_url(request)
          # Build Google OAuth authorization URL
          params = {
            client_id: @options[:client_id],
            redirect_uri: @options[:redirect_uri],
            scope: 'openid email profile',
            response_type: 'code',
            state: SecureRandom.hex
          }
          "https://accounts.google.com/o/oauth2/auth?#{URI.encode_www_form(params)}"
        end

        def exchange_code_for_user_info(code)
          # Exchange authorization code for access token and user info
          # This would make HTTP requests to Google's APIs
          # Simplified implementation
          { email: 'user@example.com', name: 'User Name' }
        end

        def create_or_update_user(user_info)
          user = Rubix::Auth::User.find_by_email(user_info[:email])
          unless user
            user = Rubix::Auth::User.create(
              email: user_info[:email],
              first_name: user_info[:name].split.first,
              last_name: user_info[:name].split.last,
              confirmed_at: Time.now
            )
          end
          user
        end
      end

      class GitHubStrategy < Strategy
        def initialize(options = {})
          super(:github, options)
        end

        def authenticate(request)
          # Redirect to GitHub OAuth
          redirect_url = build_auth_url(request)
          [302, { 'Location' => redirect_url }, []]
        end

        def callback(request)
          # Handle GitHub OAuth callback
          code = request.params['code']
          user_info = exchange_code_for_user_info(code)
          create_or_update_user(user_info)
        end

        private

        def build_auth_url(request)
          params = {
            client_id: @options[:client_id],
            redirect_uri: @options[:redirect_uri],
            scope: 'user:email',
            state: SecureRandom.hex
          }
          "https://github.com/login/oauth/authorize?#{URI.encode_www_form(params)}"
        end

        def exchange_code_for_user_info(code)
          # Exchange code for access token and user info
          # Simplified implementation
          { email: 'user@github.com', name: 'GitHub User' }
        end

        def create_or_update_user(user_info)
          user = Rubix::Auth::User.find_by_email(user_info[:email])
          unless user
            user = Rubix::Auth::User.create(
              email: user_info[:email],
              first_name: user_info[:name].split.first,
              last_name: user_info[:name].split.last,
              confirmed_at: Time.now
            )
          end
          user
        end
      end

      class Manager
        def initialize
          @strategies = {}
        end

        def register(strategy)
          @strategies[strategy.name] = strategy
        end

        def strategy(name)
          @strategies[name]
        end

        def authenticate(name, request)
          strategy = @strategies[name]
          return [404, {}, ['Strategy not found']] unless strategy

          strategy.authenticate(request)
        end

        def callback(name, request)
          strategy = @strategies[name]
          return nil unless strategy

          strategy.callback(request)
        end
      end
    end
  end
end
