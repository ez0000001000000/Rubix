# Logging and monitoring system
# This file contains logging infrastructure and monitoring capabilities

module Rubix
  module Logging
    # Logger class with multiple output formats and levels
    class Logger
      attr_accessor :level, :formatter, :outputs

      LEVELS = {
        debug: 0,
        info: 1,
        warn: 2,
        error: 3,
        fatal: 4,
        unknown: 5
      }.freeze

      def initialize(config = {})
        @level = LEVELS[config[:level]&.to_sym] || LEVELS[:info]
        @formatter = create_formatter(config[:format] || :simple)
        @outputs = create_outputs(config[:file], config[:outputs] || [:stdout])
        @buffer = []
        @buffer_size = config[:buffer_size] || 1000
        @flush_interval = config[:flush_interval] || 5
        @last_flush = Time.now

        start_background_flusher if config[:async]
      end

      def debug(message, context = {})
        log(:debug, message, context)
      end

      def info(message, context = {})
        log(:info, message, context)
      end

      def warn(message, context = {})
        log(:warn, message, context)
      end

      def error(message, context = {})
        log(:error, message, context)
      end

      def fatal(message, context = {})
        log(:fatal, message, context)
      end

      def unknown(message, context = {})
        log(:unknown, message, context)
      end

      def log(level, message, context = {})
        return if LEVELS[level] < @level

        entry = create_log_entry(level, message, context)
        formatted_entry = @formatter.format(entry)

        if async?
          @buffer << formatted_entry
          flush_buffer if should_flush?
        else
          write_to_outputs(formatted_entry)
        end
      end

      def flush
        return if @buffer.empty?

        @outputs.each do |output|
          @buffer.each { |entry| output.write(entry) }
        end

        @buffer.clear
        @last_flush = Time.now
      end

      def close
        flush
        @outputs.each(&:close)
      end

      def add_output(output)
        @outputs << output
      end

      def remove_output(output)
        @outputs.delete(output)
      end

      def with_context(context)
        old_context = @current_context
        @current_context = (@current_context || {}).merge(context)
        yield
      ensure
        @current_context = old_context
      end

      def benchmark(name, &block)
        start_time = Time.now
        result = yield
        duration = ((Time.now - start_time) * 1000).round(2)

        info("#{name} completed", duration: duration, result: result.inspect)
        result
      end

      def count(metric, increment = 1)
        @counters ||= {}
        @counters[metric] ||= 0
        @counters[metric] += increment

        info("Counter #{metric}", count: @counters[metric])
      end

      def timing(metric, duration)
        info("Timing #{metric}", duration: duration)
      end

      private

      def create_formatter(format)
        case format.to_sym
        when :json then JSONFormatter.new
        when :logfmt then LogfmtFormatter.new
        when :colored then ColoredFormatter.new
        else SimpleFormatter.new
        end
      end

      def create_outputs(file_path, output_types)
        outputs = []

        output_types.each do |type|
          case type.to_sym
          when :stdout then outputs << StdoutOutput.new
          when :stderr then outputs << StderrOutput.new
          when :file then outputs << FileOutput.new(file_path) if file_path
          when :syslog then outputs << SyslogOutput.new
          end
        end

        outputs
      end

      def create_log_entry(level, message, context)
        {
          timestamp: Time.now.iso8601,
          level: level.to_s.upcase,
          message: message,
          context: (@current_context || {}).merge(context),
          pid: Process.pid,
          thread_id: Thread.current.object_id,
          hostname: Socket.gethostname rescue 'unknown'
        }
      end

      def async?
        @async_thread&.alive?
      end

      def should_flush?
        @buffer.size >= @buffer_size || (Time.now - @last_flush) >= @flush_interval
      end

      def write_to_outputs(entry)
        @outputs.each { |output| output.write(entry) }
      end

      def start_background_flusher
        @async_thread = Thread.new do
          loop do
            sleep @flush_interval
            flush
          end
        end
      end

      # Formatters
      class SimpleFormatter
        def format(entry)
          timestamp = Time.parse(entry[:timestamp]).strftime('%Y-%m-%d %H:%M:%S')
          context_str = entry[:context].any? ? " #{entry[:context]}" : ''
          "[#{timestamp}] #{entry[:level]} -- #{entry[:message]}#{context_str}\n"
        end
      end

      class JSONFormatter
        def format(entry)
          "#{entry.to_json}\n"
        end
      end

      class LogfmtFormatter
        def format(entry)
          parts = []
          parts << "ts=#{entry[:timestamp]}"
          parts << "level=#{entry[:level]}"
          parts << "msg=\"#{entry[:message]}\""
          parts << "pid=#{entry[:pid]}"
          parts << "thread_id=#{entry[:thread_id]}"
          parts << "hostname=#{entry[:hostname]}"

          entry[:context].each do |key, value|
            parts << "#{key}=\"#{value}\""
          end

          "#{parts.join(' ')}\n"
        end
      end

      class ColoredFormatter
        COLORS = {
          DEBUG: "\e[36m",  # Cyan
          INFO: "\e[32m",   # Green
          WARN: "\e[33m",   # Yellow
          ERROR: "\e[31m",  # Red
          FATAL: "\e[35m",  # Magenta
          UNKNOWN: "\e[37m" # White
        }.freeze

        RESET = "\e[0m".freeze

        def format(entry)
          timestamp = Time.parse(entry[:timestamp]).strftime('%Y-%m-%d %H:%M:%S')
          color = COLORS[entry[:level].to_sym] || COLORS[:UNKNOWN]
          context_str = entry[:context].any? ? " #{entry[:context]}" : ''
          "#{color}[#{timestamp}] #{entry[:level]} -- #{entry[:message]}#{context_str}#{RESET}\n"
        end
      end

      # Outputs
      class StdoutOutput
        def write(entry)
          $stdout.write(entry)
          $stdout.flush
        end

        def close
          # STDOUT doesn't need to be closed
        end
      end

      class StderrOutput
        def write(entry)
          $stderr.write(entry)
          $stderr.flush
        end

        def close
          # STDERR doesn't need to be closed
        end
      end

      class FileOutput
        def initialize(file_path)
          @file_path = file_path
          @file = File.open(file_path, 'a')
          @file.sync = true
        end

        def write(entry)
          @file.write(entry)
        end

        def close
          @file.close
        end
      end

      class SyslogOutput
        def initialize(facility = 'user')
          require 'syslog'
          @syslog = Syslog.open('rubix', Syslog::LOG_PID, Syslog.const_get("LOG_#{facility.upcase}"))
        end

        def write(entry)
          level = case entry[:level]
                  when 'DEBUG' then Syslog::LOG_DEBUG
                  when 'INFO' then Syslog::LOG_INFO
                  when 'WARN' then Syslog::LOG_WARNING
                  when 'ERROR' then Syslog::LOG_ERR
                  when 'FATAL' then Syslog::LOG_CRIT
                  else Syslog::LOG_INFO
                  end

          @syslog.log(level, entry[:message])
        end

        def close
          @syslog.close
        end
      end

      class NullOutput
        def write(entry)
          # Do nothing
        end

        def close
          # Nothing to close
        end
      end
    end

    # Metrics and monitoring
    class Metrics
      attr_reader :counters, :gauges, :histograms, :timers

      def initialize
        @counters = {}
        @gauges = {}
        @histograms = {}
        @timers = {}
        @mutex = Mutex.new
      end

      def increment(counter, value = 1)
        @mutex.synchronize do
          @counters[counter] ||= 0
          @counters[counter] += value
        end
      end

      def decrement(counter, value = 1)
        increment(counter, -value)
      end

      def gauge(name, value)
        @mutex.synchronize do
          @gauges[name] = value
        end
      end

      def timing(name, duration)
        @mutex.synchronize do
          @timers[name] ||= []
          @timers[name] << duration
          # Keep only last 1000 measurements
          @timers[name] = @timers[name].last(1000)
        end
      end

      def histogram(name, value)
        @mutex.synchronize do
          @histograms[name] ||= []
          @histograms[name] << value
          # Keep only last 1000 measurements
          @histograms[name] = @histograms[name].last(1000)
        end
      end

      def measure(name, &block)
        start_time = Time.now
        result = yield
        duration = ((Time.now - start_time) * 1000).round(2)
        timing(name, duration)
        result
      end

      def stats
        @mutex.synchronize do
          {
            counters: @counters.dup,
            gauges: @gauges.dup,
            timers: timer_stats,
            histograms: histogram_stats
          }
        end
      end

      def reset
        @mutex.synchronize do
          @counters.clear
          @gauges.clear
          @histograms.clear
          @timers.clear
        end
      end

      private

      def timer_stats
        @timers.each_with_object({}) do |(name, measurements), stats|
          next if measurements.empty?

          sorted = measurements.sort
          stats[name] = {
            count: measurements.size,
            min: sorted.first,
            max: sorted.last,
            mean: (measurements.sum / measurements.size.to_f).round(2),
            median: median(sorted),
            p95: percentile(sorted, 95),
            p99: percentile(sorted, 99)
          }
        end
      end

      def histogram_stats
        @histograms.each_with_object({}) do |(name, values), stats|
          next if values.empty?

          sorted = values.sort
          stats[name] = {
            count: values.size,
            min: sorted.first,
            max: sorted.last,
            mean: (values.sum / values.size.to_f).round(2),
            median: median(sorted),
            p95: percentile(sorted, 95),
            p99: percentile(sorted, 99)
          }
        end
      end

      def median(sorted_array)
        len = sorted_array.length
        if len.odd?
          sorted_array[len / 2]
        else
          (sorted_array[len / 2 - 1] + sorted_array[len / 2]) / 2.0
        end
      end

      def percentile(sorted_array, percentile)
        return nil if sorted_array.empty?

        index = (percentile / 100.0 * (sorted_array.length - 1)).round
        sorted_array[index]
      end
    end

    # Health checks
    class HealthChecker
      def initialize
        @checks = {}
      end

      def register(name, &block)
        @checks[name] = block
      end

      def check(name)
        return { status: 'not_found', name: name } unless @checks.key?(name)

        begin
          result = @checks[name].call
          result.is_a?(Hash) ? result.merge(name: name) : { status: result ? 'healthy' : 'unhealthy', name: name }
        rescue => e
          { status: 'error', name: name, error: e.message }
        end
      end

      def check_all
        results = {}
        @checks.each_key do |name|
          results[name] = check(name)
        end
        results
      end

      def healthy?
        check_all.values.all? { |result| result[:status] == 'healthy' }
      end

      def summary
        all_results = check_all.values
        healthy_count = all_results.count { |r| r[:status] == 'healthy' }
        total_count = all_results.size

        {
          healthy: healthy_count,
          total: total_count,
          status: healthy_count == total_count ? 'healthy' : 'unhealthy',
          checks: all_results
        }
      end
    end

    # Structured logging helpers
    module StructuredLogging
      def log_request(request, response, duration)
        Rubix.logger.info('HTTP Request', {
          method: request.method,
          path: request.path,
          status: response.status,
          duration: duration,
          ip: request.ip,
          user_agent: request.user_agent
        })
      end

      def log_database_query(sql, duration, result_count = nil)
        Rubix.logger.debug('Database Query', {
          sql: sql,
          duration: duration,
          result_count: result_count
        })
      end

      def log_cache_operation(operation, key, hit = nil, duration = nil)
        Rubix.logger.debug('Cache Operation', {
          operation: operation,
          key: key,
          hit: hit,
          duration: duration
        })
      end

      def log_user_action(user, action, resource = nil, metadata = {})
        Rubix.logger.info('User Action', {
          user_id: user&.id,
          action: action,
          resource: resource,
          metadata: metadata
        })
      end

      def log_error(error, context = {})
        Rubix.logger.error('Application Error', {
          error_class: error.class.name,
          message: error.message,
          backtrace: error.backtrace&.first(10),
          context: context
        })
      end

      def log_performance(metric, value, tags = {})
        Rubix.logger.info('Performance Metric', {
          metric: metric,
          value: value,
          tags: tags
        })
      end
    end

    # Log analysis and reporting
    class LogAnalyzer
      def initialize(log_file)
        @log_file = log_file
        @parsed_logs = []
      end

      def analyze
        parse_logs
        generate_report
      end

      def parse_logs
        @parsed_logs = []

        File.foreach(@log_file) do |line|
          next if line.strip.empty?

          begin
            if line.include?('{') && line.include?('}')
              # JSON format
              parsed = JSON.parse(line, symbolize_names: true)
              @parsed_logs << parsed
            else
              # Simple format parsing
              parsed = parse_simple_line(line)
              @parsed_logs << parsed if parsed
            end
          rescue JSON::ParserError, ArgumentError
            # Skip unparseable lines
            next
          end
        end
      end

      def generate_report
        return {} if @parsed_logs.empty?

        {
          total_entries: @parsed_logs.size,
          time_range: time_range,
          level_distribution: level_distribution,
          error_rate: error_rate,
          top_messages: top_messages,
          performance_metrics: performance_metrics,
          user_activity: user_activity
        }
      end

      def filter_by_level(level)
        @parsed_logs.select { |log| log[:level] == level.to_s.upcase }
      end

      def filter_by_time_range(start_time, end_time)
        @parsed_logs.select do |log|
          timestamp = Time.parse(log[:timestamp])
          timestamp >= start_time && timestamp <= end_time
        end
      end

      def search_messages(pattern)
        @parsed_logs.select do |log|
          log[:message] =~ pattern
        end
      end

      private

      def parse_simple_line(line)
        # Simple regex parsing for basic format
        pattern = /^\[([^\]]+)\]\s+(\w+)\s+--\s+(.+)$/
        match = line.match(pattern)

        if match
          {
            timestamp: match[1],
            level: match[2],
            message: match[3],
            context: {}
          }
        end
      end

      def time_range
        return nil if @parsed_logs.empty?

        timestamps = @parsed_logs.map { |log| Time.parse(log[:timestamp]) }
        {
          start: timestamps.min.iso8601,
          end: timestamps.max.iso8601,
          duration: (timestamps.max - timestamps.min)
        }
      end

      def level_distribution
        @parsed_logs.group_by { |log| log[:level] }.transform_values(&:size)
      end

      def error_rate
        total = @parsed_logs.size
        errors = @parsed_logs.count { |log| %w[ERROR FATAL].include?(log[:level]) }
        total > 0 ? (errors.to_f / total * 100).round(2) : 0
      end

      def top_messages(limit = 10)
        messages = @parsed_logs.group_by { |log| log[:message] }.transform_values(&:size)
        messages.sort_by { |_, count| -count }.first(limit).to_h
      end

      def performance_metrics
        perf_logs = @parsed_logs.select { |log| log[:context]&.key?(:duration) }
        return {} if perf_logs.empty?

        durations = perf_logs.map { |log| log[:context][:duration] }.compact
        {
          count: durations.size,
          average: (durations.sum / durations.size.to_f).round(2),
          min: durations.min,
          max: durations.max,
          p95: percentile(durations.sort, 95)
        }
      end

      def user_activity
        user_logs = @parsed_logs.select { |log| log[:context]&.key?(:user_id) }
        user_logs.group_by { |log| log[:context][:user_id] }.transform_values(&:size)
      end

      def percentile(sorted_array, percentile)
        return nil if sorted_array.empty?

        index = (percentile / 100.0 * (sorted_array.length - 1)).round
        sorted_array[index]
      end
    end

    # Alerting system
    class Alerter
      def initialize(config = {})
        @config = config
        @alerts = []
      end

      def alert(level, message, context = {})
        alert_data = {
          id: SecureRandom.uuid,
          level: level,
          message: message,
          context: context,
          timestamp: Time.now.iso8601
        }

        @alerts << alert_data

        # Log the alert
        Rubix.logger.send(level, "ALERT: #{message}", context)

        # Send notifications based on level
        send_notifications(alert_data) if should_notify?(level)

        alert_data
      end

      def error(message, context = {})
        alert(:error, message, context)
      end

      def warning(message, context = {})
        alert(:warn, message, context)
      end

      def info(message, context = {})
        alert(:info, message, context)
      end

      def critical(message, context = {})
        alert(:fatal, message, context)
      end

      def alerts_since(time)
        @alerts.select { |alert| Time.parse(alert[:timestamp]) >= time }
      end

      def alerts_by_level(level)
        @alerts.select { |alert| alert[:level] == level }
      end

      def clear_old_alerts(older_than = 24.hours.ago)
        @alerts.reject! { |alert| Time.parse(alert[:timestamp]) < older_than }
      end

      private

      def should_notify?(level)
        notification_levels = @config[:notify_levels] || [:error, :fatal]
        notification_levels.include?(level.to_sym)
      end

      def send_notifications(alert_data)
        # Email notifications
        if @config[:email]
          send_email_notification(alert_data)
        end

        # Slack notifications
        if @config[:slack]
          send_slack_notification(alert_data)
        end

        # SMS notifications
        if @config[:sms]
          send_sms_notification(alert_data)
        end

        # Webhook notifications
        if @config[:webhook]
          send_webhook_notification(alert_data)
        end
      end

      def send_email_notification(alert)
        # Implementation for email sending
        puts "Sending email alert: #{alert[:message]}"
      end

      def send_slack_notification(alert)
        # Implementation for Slack notification
        puts "Sending Slack alert: #{alert[:message]}"
      end

      def send_sms_notification(alert)
        # Implementation for SMS sending
        puts "Sending SMS alert: #{alert[:message]}"
      end

      def send_webhook_notification(alert)
        # Implementation for webhook
        puts "Sending webhook alert: #{alert[:message]}"
      end
    end

    # Application monitoring
    class Monitor
      def initialize
        @health_checker = HealthChecker.new
        @metrics = Metrics.new
        @alerter = Alerter.new
        @start_time = Time.now
      end

      def uptime
        Time.now - @start_time
      end

      def memory_usage
        Rubix::Utils::SystemHelper.memory_usage
      end

      def cpu_usage
        # Simplified CPU usage calculation
        0.0
      end

      def thread_count
        Thread.list.size
      end

      def database_connections
        # Query database for connection count
        0
      rescue
        0
      end

      def cache_hit_rate
        # Calculate cache hit rate
        0.0
      rescue
        0.0
      end

      def request_rate
        # Calculate requests per second
        0.0
      end

      def error_rate
        # Calculate error rate
        0.0
      end

      def health_status
        @health_checker.summary
      end

      def metrics_snapshot
        @metrics.stats
      end

      def alert(message, level = :warn, context = {})
        @alerter.alert(level, message, context)
      end

      def check_threshold(metric, value, threshold, direction = :above)
        case direction
        when :above
          alert("Metric #{metric} is above threshold", :warn, { metric: metric, value: value, threshold: threshold }) if value > threshold
        when :below
          alert("Metric #{metric} is below threshold", :warn, { metric: metric, value: value, threshold: threshold }) if value < threshold
        end
      end

      def register_health_check(name, &block)
        @health_checker.register(name, &block)
      end

      def increment_metric(name, value = 1)
        @metrics.increment(name, value)
      end

      def gauge_metric(name, value)
        @metrics.gauge(name, value)
      end

      def timing_metric(name, duration)
        @metrics.timing(name, duration)
      end

      def measure(name, &block)
        @metrics.measure(name, &block)
      end
    end
  end
end
