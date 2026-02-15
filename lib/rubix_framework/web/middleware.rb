# Advanced web features
# This file contains API versioning, rate limiting, caching, and other advanced web features

require 'rubygems'
require 'digest'
require 'time'
require 'thread'

module Rubix
  module Web
    # API versioning
    class APIVersioning
      def initialize(app, options = {})
        @app = app
        @default_version = options[:default_version] || 'v1'
        @version_header = options[:version_header] || 'Accept-Version'
        @version_param = options[:version_param] || 'api_version'
        @supported_versions = options[:supported_versions] || ['v1']
      end

      def call(env)
        request = Request.new(env)
        version = extract_version(request)

        if @supported_versions.include?(version)
          env['api.version'] = version
          @app.call(env)
        else
          version_not_supported_response(version)
        end
      end

      private

      def extract_version(request)
        # Check header first
        version = request.headers[@version_header.downcase.tr('-', '_')]

        # Then check query parameter
        version ||= request.params[@version_param]

        # Then check path
        version ||= extract_version_from_path(request.path)

        # Default version
        version || @default_version
      end

      def extract_version_from_path(path)
        if path =~ %r{/api/(v\d+)/}
          "v#{$1}"
        end
      end

      def version_not_supported_response(requested_version)
        [406, { 'Content-Type' => 'application/json' },
         [{ error: 'API version not supported',
            requested_version: requested_version,
            supported_versions: @supported_versions }.to_json]]
      end
    end

    # Advanced rate limiting
    class AdvancedRateLimiter
      def initialize(app, options = {})
        @app = app
        @limits = options[:limits] || {}
        @store = options[:store] || MemoryStore.new
        @identifier = options[:identifier] || lambda { |env| env['REMOTE_ADDR'] }
        @burst_multiplier = options[:burst_multiplier] || 1.5
      end

      def call(env)
        identifier = @identifier.call(env)
        request = Request.new(env)

        limit_key = "#{identifier}:#{request.method}:#{request.path}"

        if within_limit?(limit_key, request.method, request.path)
          @app.call(env)
        else
          rate_limit_exceeded_response
        end
      end

      private

      def within_limit?(key, method, path)
        limit_config = find_limit_config(method, path)
        return true unless limit_config

        current_count = @store.get(key).to_i
        window_start = Time.now.to_i / limit_config[:window]

        if @store.get("#{key}:window") != window_start.to_s
          @store.set("#{key}:window", window_start.to_s)
          @store.set(key, '1')
          return true
        end

        burst_limit = (limit_config[:requests] * @burst_multiplier).to_i
        current_count < burst_limit
      end

      def find_limit_config(method, path)
        @limits.find do |pattern, config|
          method == config[:method] && path.match?(pattern)
        end&.last
      end

      def rate_limit_exceeded_response
        [429, { 'Content-Type' => 'application/json' },
         [{ error: 'Rate limit exceeded', retry_after: 60 }.to_json]]
      end

      class MemoryStore
        def initialize
          @data = {}
          @mutex = Mutex.new
        end

        def get(key)
          @mutex.synchronize { @data[key] }
        end

        def set(key, value)
          @mutex.synchronize { @data[key] = value }
        end

        def increment(key)
          @mutex.synchronize { @data[key] = @data[key].to_i + 1 }
        end
      end
    end

    # HTTP caching
    class HTTPCache
      def initialize(app, options = {})
        @app = app
        @store = options[:store] || MemoryCacheStore.new
        @default_ttl = options[:ttl] || 300
        @cacheable_methods = ['GET', 'HEAD']
        @cacheable_status_codes = [200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501]
      end

      def call(env)
        request = Request.new(env)

        if cacheable_request?(request)
          cache_key = generate_cache_key(request)

          if cached_response = @store.get(cache_key)
            return cached_response if fresh_enough?(cached_response, request)
          end

          # Make the request
          status, headers, body = @app.call(env)

          if cacheable_response?(status, headers)
            cached_response = [status, headers, body]
            ttl = extract_ttl(headers)
            @store.set(cache_key, cached_response, ttl)
          end

          [status, headers, body]
        else
          @app.call(env)
        end
      end

      private

      def cacheable_request?(request)
        @cacheable_methods.include?(request.method) &&
        !request.headers.key?('authorization') &&
        !request.headers.key?('cookie')
      end

      def cacheable_response?(status, headers)
        @cacheable_status_codes.include?(status) &&
        !headers.key?('cache-control') ||
        !headers['cache-control']&.include?('no-cache')
      end

      def generate_cache_key(request)
        key_parts = [request.method, request.path]
        key_parts << request.query_string if request.query_string
        Digest::MD5.hexdigest(key_parts.join(':'))
      end

      def fresh_enough?(cached_response, request)
        # Check if cached response is still fresh
        true # Simplified implementation
      end

      def extract_ttl(headers)
        if headers['cache-control'] =~ /max-age=(\d+)/
          $1.to_i
        else
          @default_ttl
        end
      end

      class MemoryCacheStore
        def initialize
          @data = {}
          @mutex = Mutex.new
        end

        def get(key)
          @mutex.synchronize do
            entry = @data[key]
            return nil unless entry

            if Time.now > entry[:expires_at]
              @data.delete(key)
              nil
            else
              entry[:response]
            end
          end
        end

        def set(key, response, ttl)
          expires_at = Time.now + ttl
          @mutex.synchronize do
            @data[key] = { response: response, expires_at: expires_at }
          end
        end
      end
    end

    # WebSocket support
    class WebSocketHandler
      def initialize(app)
        @app = app
        @connections = {}
        @channels = {}
      end

      def call(env)
        if websocket_request?(env)
          handle_websocket(env)
        else
          @app.call(env)
        end
      end

      def broadcast(channel, message)
        @channels[channel]&.each do |connection|
          connection.send(message)
        end
      end

      def subscribe(channel, connection)
        @channels[channel] ||= []
        @channels[channel] << connection
      end

      def unsubscribe(channel, connection)
        @channels[channel]&.delete(connection)
      end

      private

      def websocket_request?(env)
        env['HTTP_UPGRADE'] == 'websocket' &&
        env['HTTP_CONNECTION']&.include?('Upgrade')
      end

      def handle_websocket(env)
        # WebSocket handshake and connection handling
        # This is a simplified implementation
        [101, { 'Upgrade' => 'websocket', 'Connection' => 'Upgrade' }, []]
      end
    end

    # CORS middleware
    class CORS
      def initialize(app, options = {})
        @app = app
        @allow_origins = options[:allow_origins] || ['*']
        @allow_methods = options[:allow_methods] || ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        @allow_headers = options[:allow_headers] || ['*']
        @allow_credentials = options[:allow_credentials] || false
        @max_age = options[:max_age] || 86400
      end

      def call(env)
        request = Request.new(env)

        if request.options?
          handle_preflight_request
        else
          status, headers, body = @app.call(env)
          add_cors_headers(headers)
          [status, headers, body]
        end
      end

      private

      def handle_preflight_request
        headers = {
          'Access-Control-Allow-Origin' => @allow_origins.first,
          'Access-Control-Allow-Methods' => @allow_methods.join(', '),
          'Access-Control-Allow-Headers' => @allow_headers.join(', '),
          'Access-Control-Max-Age' => @max_age.to_s
        }

        headers['Access-Control-Allow-Credentials'] = 'true' if @allow_credentials

        [200, headers, []]
      end

      def add_cors_headers(headers)
        headers['Access-Control-Allow-Origin'] = @allow_origins.first
        headers['Access-Control-Allow-Methods'] = @allow_methods.join(', ')
        headers['Access-Control-Allow-Headers'] = @allow_headers.join(', ')

        if @allow_credentials
          headers['Access-Control-Allow-Credentials'] = 'true'
        end
      end
    end

    # Content negotiation
    class ContentNegotiation
      def initialize(app, options = {})
        @app = app
        @supported_formats = options[:supported_formats] || [:json, :xml, :html]
        @default_format = options[:default_format] || :json
      end

      def call(env)
        request = Request.new(env)
        requested_format = negotiate_format(request)

        env['content.format'] = requested_format

        status, headers, body = @app.call(env)

        # Set content type based on negotiated format
        headers['Content-Type'] = content_type_for_format(requested_format)

        [status, headers, body]
      end

      private

      def negotiate_format(request)
        # Check Accept header
        accept_header = request.headers['accept'] || ''

        @supported_formats.each do |format|
          mime_type = mime_type_for_format(format)
          return format if accept_header.include?(mime_type)
        end

        # Check format parameter
        format_param = request.params['format']
        return format_param.to_sym if @supported_formats.include?(format_param&.to_sym)

        # Check file extension
        if request.path =~ /\.(\w+)$/
          extension = $1.to_sym
          return extension if @supported_formats.include?(extension)
        end

        @default_format
      end

      def mime_type_for_format(format)
        case format
        when :json
          'application/json'
        when :xml
          'application/xml'
        when :html
          'text/html'
        else
          'application/octet-stream'
        end
      end

      def content_type_for_format(format)
        mime_type_for_format(format)
      end
    end

    # Request/response compression
    class Compression
      def initialize(app, options = {})
        @app = app
        @compression_level = options[:level] || 6
        @min_size = options[:min_size] || 1024
        @supported_encodings = ['gzip', 'deflate']
      end

      def call(env)
        request = Request.new(env)

        # Handle request decompression
        if request.headers['content-encoding'] == 'gzip'
          decompress_request_body(env)
        end

        # Handle response compression
        status, headers, body = @app.call(env)

        if should_compress?(request, headers, body)
          compressed_body = compress_body(body)
          headers['Content-Encoding'] = 'gzip'
          headers['Content-Length'] = compressed_body.bytesize.to_s
          body = [compressed_body]
        end

        [status, headers, body]
      end

      private

      def should_compress?(request, headers, body)
        return false unless request.headers['accept-encoding']&.include?('gzip')
        return false if headers['content-encoding']
        return false if headers['content-type']&.include?('image/')

        body_size = body.reduce(0) { |sum, chunk| sum + chunk.bytesize }
        body_size > @min_size
      end

      def compress_body(body)
        # Simplified gzip compression
        # In a real implementation, you'd use a proper compression library
        body.join
      end

      def decompress_request_body(env)
        # Decompress request body if needed
        # This is a simplified implementation
      end
    end

    # Request logging with detailed information
    class DetailedLogger
      def initialize(app, logger = nil)
        @app = app
        @logger = logger || Logger.new(STDOUT)
        @start_time = nil
      end

      def call(env)
        @start_time = Time.now
        request = Request.new(env)

        log_request(request)

        status, headers, body = @app.call(env)

        duration = Time.now - @start_time
        log_response(request, status, headers, duration)

        [status, headers, body]
      end

      private

      def log_request(request)
        @logger.info("REQUEST: #{request.method} #{request.path}")
        @logger.debug("Headers: #{request.headers.inspect}")
        @logger.debug("Params: #{request.params.inspect}")
        @logger.debug("Body: #{request.body}") unless request.body.empty?
      end

      def log_response(request, status, headers, duration)
        @logger.info("RESPONSE: #{status} in #{duration.round(4)}s")
        @logger.debug("Response Headers: #{headers.inspect}")
      end
    end

    # Security headers middleware
    class SecurityHeaders
      def initialize(app, options = {})
        @app = app
        @headers = {
          'X-Frame-Options' => options[:frame_options] || 'DENY',
          'X-Content-Type-Options' => 'nosniff',
          'X-XSS-Protection' => '1; mode=block',
          'Strict-Transport-Security' => options[:hsts] || 'max-age=31536000',
          'Content-Security-Policy' => options[:csp] || "default-src 'self'",
          'Referrer-Policy' => options[:referrer_policy] || 'strict-origin-when-cross-origin'
        }
      end

      def call(env)
        status, headers, body = @app.call(env)

        @headers.each do |key, value|
          headers[key] = value unless headers.key?(key)
        end

        [status, headers, body]
      end
    end

    # Request ID middleware
    class RequestID
      def initialize(app, options = {})
        @app = app
        @header_name = options[:header_name] || 'X-Request-ID'
        @generator = options[:generator] || lambda { SecureRandom.uuid }
      end

      def call(env)
        request_id = env[@header_name] || @generator.call
        env[@header_name] = request_id
        env['request.id'] = request_id

        status, headers, body = @app.call(env)

        headers[@header_name] = request_id

        [status, headers, body]
      end
    end

    # Health check endpoint
    class HealthCheck
      def initialize(app, options = {})
        @app = app
        @health_path = options[:path] || '/health'
        @checks = options[:checks] || []
      end

      def call(env)
        request = Request.new(env)

        if request.path == @health_path && request.get?
          perform_health_check
        else
          @app.call(env)
        end
      end

      private

      def perform_health_check
        results = {}
        healthy = true

        @checks.each do |check|
          begin
            result = check.call
            results[check.name] = { status: 'ok', details: result }
          rescue => e
            results[check.name] = { status: 'error', error: e.message }
            healthy = false
          end
        end

        status = healthy ? 200 : 503
        body = { status: healthy ? 'healthy' : 'unhealthy', checks: results }.to_json

        [status, { 'Content-Type' => 'application/json' }, [body]]
      end
    end

    # Static file serving with advanced features
    class AdvancedStatic
      def initialize(app, root, options = {})
        @app = app
        @root = root
        @url_prefix = options[:url_prefix] || '/static'
        @cache_control = options[:cache_control] || 'public, max-age=31536000'
        @index_files = options[:index_files] || ['index.html']
        @gzip = options[:gzip] || true
      end

      def call(env)
        request = Request.new(env)

        if request.path.start_with?(@url_prefix)
          serve_static_file(request)
        else
          @app.call(env)
        end
      end

      private

      def serve_static_file(request)
        file_path = resolve_file_path(request.path)

        if File.exist?(file_path) && File.file?(file_path)
          serve_file(file_path, request)
        else
          [404, { 'Content-Type' => 'text/plain' }, ['File not found']]
        end
      end

      def resolve_file_path(request_path)
        # Remove URL prefix and resolve to file system path
        relative_path = request_path.sub(@url_prefix, '')
        File.join(@root, relative_path)
      end

      def serve_file(file_path, request)
        # Check if file is within allowed directory
        return [403, {}, ['Forbidden']] unless allowed_path?(file_path)

        # Set cache headers
        headers = {
          'Content-Type' => mime_type(file_path),
          'Cache-Control' => @cache_control,
          'Last-Modified' => File.mtime(file_path).httpdate,
          'ETag' => etag(file_path)
        }

        # Handle conditional requests
        if not_modified?(request, file_path)
          return [304, headers, []]
        end

        # Handle gzip compression
        if @gzip && accepts_gzip?(request)
          gzipped_path = "#{file_path}.gz"
          if File.exist?(gzipped_path)
            headers['Content-Encoding'] = 'gzip'
            file_path = gzipped_path
          end
        end

        [200, headers, [File.read(file_path)]]
      end

      def allowed_path?(path)
        Pathname.new(path).expand_path.to_s.start_with?(Pathname.new(@root).expand_path.to_s)
      end

      def mime_type(path)
        # Simple MIME type detection
        case File.extname(path)
        when '.html' then 'text/html'
        when '.css' then 'text/css'
        when '.js' then 'application/javascript'
        when '.png' then 'image/png'
        when '.jpg', '.jpeg' then 'image/jpeg'
        when '.gif' then 'image/gif'
        else 'application/octet-stream'
        end
      end

      def etag(path)
        Digest::MD5.file(path).hexdigest
      end

      def not_modified?(request, path)
        if_modified_since = request.headers['if-modified-since']
        if_none_match = request.headers['if-none-match']

        return false unless if_modified_since || if_none_match

        file_mtime = File.mtime(path)

        if if_modified_since
          request_time = Time.httpdate(if_modified_since) rescue nil
          return true if request_time && file_mtime <= request_time
        end

        if if_none_match && if_none_match == etag(path)
          return true
        end

        false
      end

      def accepts_gzip?(request)
        accept_encoding = request.headers['accept-encoding'] || ''
        accept_encoding.include?('gzip')
      end
    end

    # Request timeout middleware
    class Timeout
      def initialize(app, timeout_seconds = 30)
        @app = app
        @timeout_seconds = timeout_seconds
      end

      def call(env)
        timeout_thread = Thread.new do
          sleep @timeout_seconds
          # In a real implementation, you'd kill the main thread
          raise Timeout::Error, "Request timed out after #{@timeout_seconds} seconds"
        end

        begin
          status, headers, body = @app.call(env)
          timeout_thread.kill
          [status, headers, body]
        rescue Timeout::Error => e
          timeout_thread.kill
          [408, { 'Content-Type' => 'text/plain' }, ['Request Timeout']]
        end
      end
    end
  end
end
