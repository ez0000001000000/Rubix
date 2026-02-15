# Web server and routing system
# This file contains the web server, router, controllers, and middleware

module Rubix
  module Web
    # HTTP Request class
    class Request
      attr_reader :env, :params, :headers, :method, :path, :query_string, :body

      def initialize(env)
        @env = env
        @method = env['REQUEST_METHOD']
        @path = env['PATH_INFO']
        @query_string = env['QUERY_STRING']
        @headers = extract_headers(env)
        @params = parse_params
        @body = parse_body
      end

      def get?
        @method == 'GET'
      end

      def post?
        @method == 'POST'
      end

      def put?
        @method == 'PUT'
      end

      def patch?
        @method == 'PATCH'
      end

      def delete?
        @method == 'DELETE'
      end

      def head?
        @method == 'HEAD'
      end

      def options?
        @method == 'OPTIONS'
      end

      def ssl?
        env['HTTPS'] == 'on' || env['HTTP_X_FORWARDED_PROTO'] == 'https'
      end

      def xhr?
        env['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest'
      end

      def json?
        content_type&.include?('application/json')
      end

      def content_type
        @headers['Content-Type']
      end

      def user_agent
        @headers['User-Agent']
      end

      def ip
        env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip ||
        env['HTTP_X_REAL_IP'] ||
        env['REMOTE_ADDR']
      end

      def session
        env['rack.session']
      end

      def cookies
        @cookies ||= parse_cookies
      end

      def cookie(name)
        cookies[name]
      end

      def referrer
        @headers['Referer'] || @headers['Referrer']
      end

      def accept
        @headers['Accept']
      end

      def accept_language
        @headers['Accept-Language']
      end

      def authorization
        @headers['Authorization']
      end

      def basic_auth
        if authorization&.start_with?('Basic ')
          encoded = authorization[6..-1]
          decoded = Base64.decode64(encoded)
          username, password = decoded.split(':', 2)
          [username, password]
        end
      end

      def bearer_token
        if authorization&.start_with?('Bearer ')
          authorization[7..-1]
        end
      end

      private

      def extract_headers(env)
        headers = {}
        env.each do |key, value|
          if key.start_with?('HTTP_')
            header_name = key[5..-1].split('_').map(&:capitalize).join('-')
            headers[header_name] = value
          elsif key.start_with?('CONTENT_')
            header_name = key.split('_').map(&:capitalize).join('-')
            headers[header_name] = value
          end
        end
        headers
      end

      def parse_params
        params = {}

        # Parse query string
        if @query_string && !@query_string.empty?
          URI.decode_www_form(@query_string).each do |key, value|
            params[key] = value
          end
        end

        # Parse POST body for form data
        if post? && content_type&.include?('application/x-www-form-urlencoded')
          body_params = URI.decode_www_form(@body || '').to_h
          params.merge!(body_params)
        end

        # Parse JSON body
        if json? && @body
          json_params = JSON.parse(@body, symbolize_names: true)
          params.merge!(json_params) if json_params.is_a?(Hash)
        end

        params.symbolize_keys
      end

      def parse_body
        return nil unless env['rack.input']

        env['rack.input'].rewind
        env['rack.input'].read
      end

      def parse_cookies
        cookie_header = env['HTTP_COOKIE']
        return {} unless cookie_header

        cookies = {}
        cookie_header.split(';').each do |cookie|
          name, value = cookie.strip.split('=', 2)
          cookies[name] = value if name && value
        end
        cookies
      end
    end

    # HTTP Response class
    class Response
      attr_reader :status, :headers, :body

      def initialize(status = 200, headers = {}, body = [])
        @status = status
        @headers = headers
        @body = body.is_a?(Array) ? body : [body]
      end

      def status=(value)
        @status = value
      end

      def [](key)
        @headers[key]
      end

      def []=(key, value)
        @headers[key] = value
      end

      def set_cookie(name, value, options = {})
        cookie_options = {
          value: value,
          path: options[:path] || '/',
          expires: options[:expires],
          domain: options[:domain],
          secure: options[:secure] || false,
          httponly: options[:httponly] || false,
          samesite: options[:samesite] || 'Lax'
        }.compact

        cookie_string = "#{name}=#{cookie_options[:value]}"
        cookie_string << "; Path=#{cookie_options[:path]}" if cookie_options[:path]
        cookie_string << "; Expires=#{cookie_options[:expires].httpdate}" if cookie_options[:expires]
        cookie_string << "; Domain=#{cookie_options[:domain]}" if cookie_options[:domain]
        cookie_string << "; Secure" if cookie_options[:secure]
        cookie_string << "; HttpOnly" if cookie_options[:httponly]
        cookie_string << "; SameSite=#{cookie_options[:samesite]}" if cookie_options[:samesite]

        @headers['Set-Cookie'] ||= []
        @headers['Set-Cookie'] << cookie_string
      end

      def delete_cookie(name, options = {})
        set_cookie(name, '', options.merge(expires: Time.at(0)))
      end

      def redirect(location, status = 302)
        @status = status
        @headers['Location'] = location
        @body = ["Redirecting to #{location}"]
      end

      def json(data, status = 200)
        @status = status
        @headers['Content-Type'] = 'application/json'
        @body = [data.to_json]
      end

      def html(content, status = 200)
        @status = status
        @headers['Content-Type'] = 'text/html'
        @body = [content]
      end

      def text(content, status = 200)
        @status = status
        @headers['Content-Type'] = 'text/plain'
        @body = [content]
      end

      def xml(content, status = 200)
        @status = status
        @headers['Content-Type'] = 'application/xml'
        @body = [content]
      end

      def file(path, options = {})
        if File.exist?(path)
          @status = 200
          @headers['Content-Type'] = options[:content_type] || Rack::Mime.mime_type(File.extname(path))
          @headers['Content-Length'] = File.size(path).to_s
          @headers['Content-Disposition'] = "attachment; filename=\"#{File.basename(path)}\"" if options[:attachment]
          @body = File.open(path, 'rb')
        else
          @status = 404
          @body = ['File not found']
        end
      end

      def not_found(message = 'Not Found')
        @status = 404
        @headers['Content-Type'] = 'text/plain'
        @body = [message]
      end

      def unauthorized(message = 'Unauthorized')
        @status = 401
        @headers['Content-Type'] = 'text/plain'
        @body = [message]
      end

      def forbidden(message = 'Forbidden')
        @status = 403
        @headers['Content-Type'] = 'text/plain'
        @body = [message]
      end

      def bad_request(message = 'Bad Request')
        @status = 400
        @headers['Content-Type'] = 'text/plain'
        @body = [message]
      end

      def internal_server_error(message = 'Internal Server Error')
        @status = 500
        @headers['Content-Type'] = 'text/plain'
        @body = [message]
      end

      def to_a
        [@status, @headers, @body]
      end
    end

    # Router class for handling HTTP routes
    class Router
      attr_reader :routes

      def initialize(routes = {})
        @routes = routes
        @middleware_stack = []
      end

      def use(middleware, *args)
        @middleware_stack << [middleware, args]
      end

      def call(env)
        request = Request.new(env)
        response = Response.new

        # Apply middleware
        app = build_middleware_stack

        begin
          result = app.call(request, response)
          result.is_a?(Array) ? result : response.to_a
        rescue => e
          handle_error(e, response)
        end
      end

      def match(method, path)
        route_key = [method.upcase, path]
        @routes[route_key] || match_dynamic_route(method, path)
      end

      def add_route(method, path, controller, action)
        @routes[[method.upcase, path]] = [controller, action]
      end

      def resources(resource_name, options = {})
        controller = options[:controller] || "#{resource_name.classify.pluralize}Controller".constantize
        path_prefix = options[:path] || resource_name.to_s.pluralize

        # Standard REST routes
        get "/#{path_prefix}", controller, :index
        get "/#{path_prefix}/new", controller, :new
        post "/#{path_prefix}", controller, :create
        get "/#{path_prefix}/:id", controller, :show
        get "/#{path_prefix}/:id/edit", controller, :edit
        put "/#{path_prefix}/:id", controller, :update
        patch "/#{path_prefix}/:id", controller, :update
        delete "/#{path_prefix}/:id", controller, :destroy
      end

      def resource(resource_name, options = {})
        controller = options[:controller] || "#{resource_name.classify}Controller".constantize
        path_prefix = options[:path] || resource_name.to_s

        # Singular resource routes
        get "/#{path_prefix}", controller, :show
        get "/#{path_prefix}/new", controller, :new
        post "/#{path_prefix}", controller, :create
        get "/#{path_prefix}/edit", controller, :edit
        put "/#{path_prefix}", controller, :update
        patch "/#{path_prefix}", controller, :update
        delete "/#{path_prefix}", controller, :destroy
      end

      def namespace(namespace_name, &block)
        old_routes = @routes.dup
        @routes.clear

        yield

        namespaced_routes = {}
        @routes.each do |route_key, route_value|
          method, path = route_key
          namespaced_path = "/#{namespace_name}#{path}"
          namespaced_routes[[method, namespaced_path]] = route_value
        end

        @routes = old_routes.merge(namespaced_routes)
      end

      def scope(options = {}, &block)
        path_prefix = options[:path]
        module_name = options[:module]

        old_routes = @routes.dup
        @routes.clear

        yield

        scoped_routes = {}
        @routes.each do |route_key, route_value|
          method, path = route_key
          scoped_path = path_prefix ? "#{path_prefix}#{path}" : path
          scoped_controller = module_name ? "#{module_name}::#{route_value.first}" : route_value.first
          scoped_routes[[method, scoped_path]] = [scoped_controller, route_value.last]
        end

        @routes = old_routes.merge(scoped_routes)
      end

      def root(controller, action)
        get '/', controller, action
      end

      def mount(app, at:)
        @routes[[nil, at]] = app
      end

      private

      def build_middleware_stack
        app = lambda do |request, response|
          route_info = match(request.method, request.path)
          if route_info.is_a?(Array)
            controller_class, action = route_info
            dispatch_to_controller(controller_class, action, request, response)
          elsif route_info.respond_to?(:call)
            # Mounted Rack app
            route_info.call(request.env)
          else
            response.not_found
          end
        end

        @middleware_stack.reverse.each do |middleware, args|
          app = middleware.new(app, *args)
        end

        app
      end

      def dispatch_to_controller(controller_class, action, request, response)
        controller = controller_class.new(request, response)
        if controller.respond_to?(action)
          controller.send(action)
        else
          response.not_found("Action #{action} not found")
        end
      rescue => e
        handle_error(e, response)
      end

      def match_dynamic_route(method, path)
        @routes.each do |route_key, route_value|
          route_method, route_path = route_key
          next unless route_method == method.upcase || route_method.nil?

          if route_path.include?(':')
            params = extract_params_from_path(route_path, path)
            return route_value if params
          end
        end
        nil
      end

      def extract_params_from_path(route_path, request_path)
        route_parts = route_path.split('/')
        request_parts = request_path.split('/')

        return nil unless route_parts.length == request_parts.length

        params = {}
        route_parts.each_with_index do |part, index|
          if part.start_with?(':')
            param_name = part[1..-1].to_sym
            params[param_name] = request_parts[index]
          elsif part != request_parts[index]
            return nil
          end
        end

        params
      end

      def handle_error(error, response)
        case error
        when Rubix::Database::RecordNotFound
          response.not_found(error.message)
        when Rubix::Auth::AuthenticationError
          response.unauthorized(error.message)
        when Rubix::Auth::AuthorizationError
          response.forbidden(error.message)
        when Rubix::ValidationError
          response.bad_request(error.message)
        else
          Rubix.logger.error("Unhandled error: #{error.message}\n#{error.backtrace.join("\n")}")
          response.internal_server_error
        end
      end
    end

    # Base controller class
    class Controller
      attr_reader :request, :response, :params, :session, :cookies

      def initialize(request, response)
        @request = request
        @response = response
        @params = request.params
        @session = request.session
        @cookies = request.cookies
      end

      def render(options = {})
        case options[:action] || action_name
        when :json
          response.json(options[:json] || {})
        when :text
          response.text(options[:text] || '')
        when :html
          content = options[:html] || render_template
          response.html(content)
        when :xml
          response.xml(options[:xml] || '')
        when :file
          response.file(options[:file], options)
        else
          response.html(render_template)
        end
      end

      def redirect_to(location, options = {})
        response.redirect(location, options[:status] || 302)
      end

      def head(status, options = {})
        response.status = status
        options.each { |key, value| response[key] = value }
        response.body = []
      end

      def json_response(data, status = 200)
        render json: data, status: status
      end

      def authenticate_user!
        unless current_user
          redirect_to '/login'
        end
      end

      def authorize!(permission)
        Rubix::Application.instance.config.authorization_manager.authorize!(current_user&.id, permission)
      end

      def current_user
        @current_user ||= begin
          if session&.authenticated?
            session.user
          elsif request.bearer_token
            Rubix::Auth::JWT.user_from_token(request.bearer_token)
          end
        end
      end

      def signed_in?
        current_user.present?
      end

      def sign_in(user)
        session.user = user if session
      end

      def sign_out
        session&.destroy!
      end

      def flash
        session[:flash] ||= {}
      end

      def flash=(value)
        session[:flash] = value
      end

      def logger
        Rubix.logger
      end

      private

      def action_name
        @action_name ||= self.class.name.demodulize.underscore.sub(/_controller$/, '').to_sym
      end

      def controller_name
        @controller_name ||= self.class.name.demodulize.underscore.sub(/_controller$/, '')
      end

      def render_template(template_name = nil)
        template_name ||= "#{controller_name}/#{action_name}"
        template_path = "app/views/#{template_name}.erb"

        if File.exist?(template_path)
          template = ERB.new(File.read(template_path))
          template.result(binding)
        else
          "<h1>Template not found: #{template_name}</h1>"
        end
      end

      def render_partial(partial_name, locals = {})
        partial_path = "app/views/#{controller_name}/_#{partial_name}.erb"

        if File.exist?(partial_path)
          template = ERB.new(File.read(partial_path))
          locals.each { |key, value| instance_variable_set("@#{key}", value) }
          template.result(binding)
        else
          "<!-- Partial not found: #{partial_name} -->"
        end
      end

      def csrf_token
        session[:csrf_token] ||= SecureRandom.hex(32)
      end

      def verify_csrf_token
        if request.post? || request.put? || request.patch? || request.delete?
          token = params[:csrf_token] || request.headers['X-CSRF-Token']
          unless token == session[:csrf_token]
            raise Rubix::Error, 'CSRF token verification failed'
          end
        end
      end
    end

    # RESTful controller base class
    class RESTController < Controller
      def index
        records = model_class.all
        json_response(records.map(&:serializable_hash))
      end

      def show
        record = find_record
        json_response(record.serializable_hash)
      end

      def create
        record = model_class.new(params)
        if record.save
          json_response(record.serializable_hash, 201)
        else
          json_response({ errors: record.errors.full_messages }, 422)
        end
      end

      def update
        record = find_record
        if record.update(params)
          json_response(record.serializable_hash)
        else
          json_response({ errors: record.errors.full_messages }, 422)
        end
      end

      def destroy
        record = find_record
        record.destroy
        head :no_content
      end

      private

      def model_class
        @model_class ||= self.class.name.sub(/Controller$/, '').singularize.constantize
      end

      def find_record
        model_class.find(params[:id])
      end
    end

    # API controller base class
    class APIController < Controller
      before_action :authenticate_request
      before_action :set_default_format

      def authenticate_request
        unless current_user
          head :unauthorized
        end
      end

      def set_default_format
        response['Content-Type'] = 'application/json'
      end

      def render(options = {})
        if options[:json]
          response.json(options[:json], options[:status] || 200)
        else
          super
        end
      end
    end

    # Web server implementation
    class Server
      def initialize(config, middleware_stack = [], router = nil)
        @config = config
        @middleware_stack = middleware_stack
        @router = router || Router.new
        @server = nil
      end

      def start
        configure_server
        setup_middleware
        start_server
      end

      def stop
        @server&.shutdown
      end

      private

      def configure_server
        @host = @config[:host] || '0.0.0.0'
        @port = @config[:port] || 3000
        @environment = @config[:environment] || 'development'
        @threads = @config[:threads] || 5
        @workers = @config[:workers] || 1
      end

      def setup_middleware
        # Add built-in middleware
        @middleware_stack.unshift [CommonLogger] if @config[:logging]
        @middleware_stack.unshift [ContentLength]
        @middleware_stack.unshift [ContentType, 'text/html']
        @middleware_stack.unshift [Static, @config[:static_files]] if @config[:static_files]
        @middleware_stack.unshift [SessionManager, @config[:session_config]] if @config[:session_config]
        @middleware_stack.unshift [CSRFProtection] if @config[:csrf_protection]
      end

      def start_server
        puts "Starting Rubix server on #{@host}:#{@port} in #{@environment} mode"

        app = Rack::Builder.new do
          @middleware_stack.each do |middleware, args|
            use middleware, *args
          end

          run @router
        end

        if @environment == 'development'
          Rack::Server.start(
            app: app,
            Host: @host,
            Port: @port,
            environment: @environment
          )
        else
          # Production configuration with Puma-like setup
          require 'puma'
          Puma::Server.new(app).tap do |server|
            server.min_threads = 1
            server.max_threads = @threads
            server.bind("tcp://#{@host}:#{@port}")
            server.run
          end
        end
      end
    end

    # Built-in middleware classes
    class CommonLogger
      def initialize(app)
        @app = app
      end

      def call(env)
        start_time = Time.now
        status, headers, body = @app.call(env)
        end_time = Time.now

        request = Request.new(env)
        duration = ((end_time - start_time) * 1000).round(2)

        log_line = "#{request.ip} - [#{start_time.strftime('%d/%b/%Y:%H:%M:%S %z')}] " \
                   "\"#{request.method} #{request.path} HTTP/1.1\" #{status} " \
                   "#{content_length(headers)} #{duration}ms"

        Rubix.logger.info(log_line)

        [status, headers, body]
      end

      private

      def content_length(headers)
        headers['Content-Length'] || '-'
      end
    end

    class ContentLength
      def initialize(app)
        @app = app
      end

      def call(env)
        status, headers, body = @app.call(env)

        if !headers['Content-Length'] && body.respond_to?(:length)
          headers['Content-Length'] = body.length.to_s
        end

        [status, headers, body]
      end
    end

    class ContentType
      def initialize(app, default_type = 'text/html')
        @app = app
        @default_type = default_type
      end

      def call(env)
        status, headers, body = @app.call(env)

        headers['Content-Type'] ||= @default_type

        [status, headers, body]
      end
    end

    class Static
      def initialize(app, root = 'public')
        @app = app
        @root = root
      end

      def call(env)
        request = Request.new(env)

        if request.get? && static_file?(request.path)
          file_path = File.join(@root, request.path)

          if File.exist?(file_path) && !File.directory?(file_path)
            response = Response.new
            response.file(file_path)
            return response.to_a
          end
        end

        @app.call(env)
      end

      private

      def static_file?(path)
        path =~ /\A\/[^\/]+\.[^\/]+\z/ && !path.include?('..')
      end
    end

    class SessionManager
      def initialize(app, config = {})
        @app = app
        @session_manager = Rubix::Auth::SessionManager.new(
          config[:store] || :memory,
          config
        )
      end

      def call(env)
        request = Request.new(env)

        # Load session from request
        session_id = request.cookies['session_id']
        session = session_id ? @session_manager.find(session_id) : nil

        if session
          env['rack.session'] = session
        else
          env['rack.session'] = @session_manager.create
        end

        status, headers, body = @app.call(env)

        # Save session
        if env['rack.session']
          session = env['rack.session']
          @session_manager.update(session)

          # Set session cookie
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
    end

    class CSRFProtection
      def initialize(app)
        @app = app
      end

      def call(env)
        request = Request.new(env)

        if request.post? || request.put? || request.patch? || request.delete?
          token = request.params[:csrf_token] || request.headers['X-CSRF-Token']
          session = env['rack.session']

          if session && token != session[:csrf_token]
            response = Response.new
            response.forbidden('CSRF token verification failed')
            return response.to_a
          end
        end

        @app.call(env)
      end
    end

    class CORS
      def initialize(app, options = {})
        @app = app
        @options = {
          origins: options[:origins] || ['*'],
          methods: options[:methods] || ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
          headers: options[:headers] || ['*'],
          credentials: options[:credentials] || false,
          max_age: options[:max_age] || 86400
        }
      end

      def call(env)
        request = Request.new(env)

        if request.options?
          handle_preflight_request
        else
          status, headers, body = @app.call(env)
          add_cors_headers(headers, request)
          [status, headers, body]
        end
      end

      private

      def handle_preflight_request
        headers = {}
        add_cors_headers(headers, nil)
        [200, headers, []]
      end

      def add_cors_headers(headers, request = nil)
        headers['Access-Control-Allow-Origin'] = allowed_origin(request)
        headers['Access-Control-Allow-Methods'] = @options[:methods].join(', ')
        headers['Access-Control-Allow-Headers'] = @options[:headers].join(', ')
        headers['Access-Control-Allow-Credentials'] = 'true' if @options[:credentials]
        headers['Access-Control-Max-Age'] = @options[:max_age].to_s
      end

      def allowed_origin(request)
        return @options[:origins].first if @options[:origins].include?('*')

        origin = request&.headers['Origin']
        @options[:origins].find { |allowed| allowed == origin } || @options[:origins].first
      end
    end

    class RateLimiter
      def initialize(app, options = {})
        @app = app
        @max_requests = options[:max_requests] || 100
        @window = options[:window] || 60 # seconds
        @store = options[:store] || {}
      end

      def call(env)
        request = Request.new(env)
        key = rate_limit_key(request)

        current_time = Time.now.to_i
        window_start = current_time - @window

        # Clean old entries
        @store[key] ||= []
        @store[key].select! { |timestamp| timestamp > window_start }

        if @store[key].size >= @max_requests
          response = Response.new
          response.status = 429
          response['Retry-After'] = (@store[key].first + @window - current_time).to_s
          response.text('Rate limit exceeded')
          return response.to_a
        end

        @store[key] << current_time

        status, headers, body = @app.call(env)
        headers['X-RateLimit-Limit'] = @max_requests.to_s
        headers['X-RateLimit-Remaining'] = (@max_requests - @store[key].size).to_s
        headers['X-RateLimit-Reset'] = (current_time + @window).to_s

        [status, headers, body]
      end

      private

      def rate_limit_key(request)
        "#{request.ip}:#{request.path}"
      end
    end

    class Gzip
      def initialize(app)
        @app = app
      end

      def call(env)
        request = Request.new(env)

        if supports_gzip?(request)
          status, headers, body = @app.call(env)

          if should_compress?(headers)
            compressed_body = gzip_compress(body_to_string(body))
            headers['Content-Encoding'] = 'gzip'
            headers['Content-Length'] = compressed_body.bytesize.to_s
            body = [compressed_body]
          end

          [status, headers, body]
        else
          @app.call(env)
        end
      end

      private

      def supports_gzip?(request)
        accept_encoding = request.headers['Accept-Encoding']
        accept_encoding&.include?('gzip')
      end

      def should_compress?(headers)
        content_type = headers['Content-Type']
        return false unless content_type

        compressible_types = ['text/', 'application/json', 'application/xml', 'application/javascript']
        compressible_types.any? { |type| content_type.include?(type) }
      end

      def body_to_string(body)
        body.is_a?(Array) ? body.join : body.to_s
      end

      def gzip_compress(data)
        io = StringIO.new
        gz = Zlib::GzipWriter.new(io)
        gz.write(data)
        gz.close
        io.string
      end
    end

    # Asset pipeline (simplified)
    class AssetPipeline
      def initialize(app, config = {})
        @app = app
        @config = config
        @assets = {}
      end

      def call(env)
        request = Request.new(env)

        if asset_request?(request.path)
          serve_asset(request.path)
        else
          @app.call(env)
        end
      end

      private

      def asset_request?(path)
        path.start_with?('/assets/') && !path.include?('..')
      end

      def serve_asset(path)
        asset_name = path.sub('/assets/', '')
        asset_path = find_asset(asset_name)

        if asset_path && File.exist?(asset_path)
          response = Response.new
          response.status = 200
          response['Content-Type'] = mime_type(asset_path)
          response['Cache-Control'] = 'public, max-age=31536000'
          response.body = [File.read(asset_path)]
          response.to_a
        else
          [404, {}, ['Asset not found']]
        end
      end

      def find_asset(name)
        # Look in configured asset paths
        asset_paths = @config[:paths] || ['app/assets', 'public/assets']

        asset_paths.each do |path|
          full_path = File.join(path, name)
          return full_path if File.exist?(full_path)
        end

        nil
      end

      def mime_type(path)
        case File.extname(path)
        when '.css' then 'text/css'
        when '.js' then 'application/javascript'
        when '.png' then 'image/png'
        when '.jpg', '.jpeg' then 'image/jpeg'
        when '.gif' then 'image/gif'
        when '.svg' then 'image/svg+xml'
        else 'application/octet-stream'
        end
      end
    end
  end
end
