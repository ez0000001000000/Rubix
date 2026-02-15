# Advanced utilities and helpers
# This file contains advanced utility classes for data processing, caching, background jobs, and more

require 'rubygems'
require 'thread'
require 'monitor'
require 'set'
require 'digest'
require 'zlib'
require 'stringio'
require 'csv'
require 'yaml'
require 'json'
require 'time'
require 'date'

module Rubix
  module Utils
    # Advanced data structures
    class Trie
      def initialize
        @root = {}
      end

      def insert(word)
        node = @root
        word.each_char do |char|
          node[char] ||= {}
          node = node[char]
        end
        node[:end] = true
      end

      def search(word)
        node = find_node(word)
        node && node[:end]
      end

      def starts_with(prefix)
        find_node(prefix) != nil
      end

      def find_node(word)
        node = @root
        word.each_char do |char|
          return nil unless node[char]
          node = node[char]
        end
        node
      end

      def autocomplete(prefix)
        node = find_node(prefix)
        return [] unless node

        results = []
        collect_words(node, prefix, results)
        results
      end

      private

      def collect_words(node, current_word, results)
        results << current_word if node[:end]

        node.each do |char, child_node|
          next if char == :end
          collect_words(child_node, current_word + char, results)
        end
      end
    end

    class BloomFilter
      def initialize(size, hash_functions = 3)
        @size = size
        @hash_functions = hash_functions
        @bit_array = Array.new(size, false)
        @seeds = (0...hash_functions).map { |i| i * 31 + 17 }
      end

      def add(item)
        hashes = compute_hashes(item)
        hashes.each { |hash| @bit_array[hash % @size] = true }
      end

      def include?(item)
        hashes = compute_hashes(item)
        hashes.all? { |hash| @bit_array[hash % @size] }
      end

      def clear
        @bit_array.fill(false)
      end

      private

      def compute_hashes(item)
        item_str = item.to_s
        @seeds.map do |seed|
          hash = seed
          item_str.each_byte { |byte| hash = (hash * 31 + byte) & 0xFFFFFFFF }
          hash
        end
      end
    end

    class LRUCache
      def initialize(max_size)
        @max_size = max_size
        @cache = {}
        @access_order = []
        @mutex = Mutex.new
      end

      def get(key)
        @mutex.synchronize do
          return nil unless @cache.key?(key)

          update_access_order(key)
          @cache[key][:value]
        end
      end

      def set(key, value, ttl = nil)
        @mutex.synchronize do
          if @cache.key?(key)
            @cache[key][:value] = value
            @cache[key][:ttl] = ttl ? Time.now + ttl : nil
            update_access_order(key)
          else
            @cache[key] = { value: value, ttl: ttl ? Time.now + ttl : nil }
            @access_order << key

            evict_if_needed
          end
        end
      end

      def delete(key)
        @mutex.synchronize do
          @cache.delete(key)
          @access_order.delete(key)
        end
      end

      def clear
        @mutex.synchronize do
          @cache.clear
          @access_order.clear
        end
      end

      def size
        @mutex.synchronize { @cache.size }
      end

      def cleanup_expired
        @mutex.synchronize do
          expired_keys = @cache.select do |_, data|
            data[:ttl] && Time.now > data[:ttl]
          end.keys

          expired_keys.each { |key| delete(key) }
        end
      end

      private

      def update_access_order(key)
        @access_order.delete(key)
        @access_order << key
      end

      def evict_if_needed
        while @access_order.size > @max_size
          key_to_evict = @access_order.shift
          @cache.delete(key_to_evict)
        end
      end
    end

    # Advanced file processing
    class FileProcessor
      def initialize(options = {})
        @chunk_size = options[:chunk_size] || 8192
        @encoding = options[:encoding] || 'UTF-8'
        @compression = options[:compression] || false
      end

      def process_large_file(file_path, &block)
        File.open(file_path, "r:#{@encoding}") do |file|
          if @compression
            process_compressed_file(file, &block)
          else
            process_file_in_chunks(file, &block)
          end
        end
      end

      def process_csv_file(file_path, options = {}, &block)
        CSV.foreach(file_path, options) do |row|
          yield(row) if block_given?
        end
      end

      def process_json_lines_file(file_path, &block)
        File.open(file_path, "r:#{@encoding}") do |file|
          file.each_line do |line|
            next if line.strip.empty?
            json_data = JSON.parse(line.strip)
            yield(json_data) if block_given?
          end
        end
      end

      def write_compressed_file(file_path, data)
        Zlib::GzipWriter.open(file_path) do |gz|
          gz.write(data)
        end
      end

      def read_compressed_file(file_path)
        Zlib::GzipReader.open(file_path) do |gz|
          gz.read
        end
      end

      def merge_files(output_path, *input_paths)
        File.open(output_path, 'w') do |output|
          input_paths.each do |input_path|
            File.open(input_path, 'r') do |input|
              IO.copy_stream(input, output)
            end
          end
        end
      end

      def split_file(input_path, lines_per_file)
        File.open(input_path, 'r') do |input|
          file_number = 1
          output_file = nil
          line_count = 0

          input.each_line do |line|
            if line_count % lines_per_file == 0
              output_file.close if output_file
              output_file = File.open("#{input_path}.part#{file_number}", 'w')
              file_number += 1
            end

            output_file.write(line)
            line_count += 1
          end

          output_file.close if output_file
        end
      end

      private

      def process_file_in_chunks(file, &block)
        while (chunk = file.read(@chunk_size))
          yield(chunk) if block_given?
        end
      end

      def process_compressed_file(file, &block)
        gz = Zlib::GzipReader.new(file)
        process_file_in_chunks(gz, &block)
        gz.close
      end
    end

    # Background job system
    class JobQueue
      def initialize(options = {})
        @queue = Queue.new
        @workers = []
        @max_workers = options[:max_workers] || 5
        @running = false
        @mutex = Mutex.new
        @cond = ConditionVariable.new
      end

      def start
        @mutex.synchronize do
          return if @running
          @running = true

          @max_workers.times do
            @workers << Thread.new { worker_loop }
          end
        end
      end

      def stop
        @mutex.synchronize do
          @running = false
          @cond.broadcast

          @workers.each(&:join)
          @workers.clear
        end
      end

      def enqueue(job)
        @queue << job
      end

      def size
        @queue.size
      end

      def clear
        @queue.clear
      end

      private

      def worker_loop
        while @running
          job = nil

          @mutex.synchronize do
            while @running && @queue.empty?
              @cond.wait(@mutex)
            end

            job = @queue.pop if @running
          end

          execute_job(job) if job
        end
      end

      def execute_job(job)
        begin
          job.call
        rescue => e
          # Log error but don't crash the worker
          puts "Job execution error: #{e.message}"
        end
      end
    end

    class ScheduledJob
      def initialize(schedule, &block)
        @schedule = schedule
        @job = block
        @last_run = nil
        @running = false
      end

      def start
        @running = true
        Thread.new { run_loop }
      end

      def stop
        @running = false
      end

      def run_now
        execute_job
      end

      private

      def run_loop
        while @running
          if should_run?
            execute_job
            @last_run = Time.now
          end

          sleep(60) # Check every minute
        end
      end

      def should_run?
        case @schedule
        when :hourly
          @last_run.nil? || Time.now - @last_run >= 3600
        when :daily
          @last_run.nil? || Time.now.day != @last_run.day
        when :weekly
          @last_run.nil? || Time.now.wday == 0 && @last_run.wday != 0
        when :monthly
          @last_run.nil? || Time.now.month != @last_run.month
        else
          false
        end
      end

      def execute_job
        begin
          @job.call
        rescue => e
          puts "Scheduled job error: #{e.message}"
        end
      end
    end

    # Advanced string processing
    class StringProcessor
      def initialize(text)
        @text = text.dup
      end

      def extract_emails
        @text.scan(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/)
      end

      def extract_urls
        @text.scan(%r{https?://[^\s<>"{}|\\^`\[\]]+})
      end

      def extract_phone_numbers
        @text.scan(/(?<!\d)(?:\+\d{1,3}[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}(?!\d)/)
      end

      def extract_hashtags
        @text.scan(/#\w+/)
      end

      def extract_mentions
        @text.scan(/@\w+/)
      end

      def remove_html_tags
        @text.gsub(%r{</?[^>]+>}, '')
      end

      def normalize_whitespace
        @text.gsub(/\s+/, ' ').strip
      end

      def truncate_words(max_length)
        words = @text.split
        truncated = words.take_while.with_index do |word, index|
          current_length = words[0..index].join(' ').length
          current_length <= max_length
        end

        truncated.join(' ') + (truncated.size < words.size ? '...' : '')
      end

      def to_slug
        @text.downcase
              .gsub(/[^\w\s-]/, '')
              .gsub(/[\s_-]+/, '-')
              .gsub(/^-|-$/, '')
      end

      def highlight_keywords(keywords, tag = 'mark')
        keywords.each do |keyword|
          @text.gsub!(/\b#{Regexp.escape(keyword)}\b/i, "<#{tag}>\\0</#{tag}>")
        end
        @text
      end

      def word_count
        @text.split(/\s+/).size
      end

      def reading_time(words_per_minute = 200)
        (word_count.to_f / words_per_minute).ceil
      end

      def similarity(other_text)
        text1_words = Set.new(@text.downcase.scan(/\w+/))
        text2_words = Set.new(other_text.downcase.scan(/\w+/))

        intersection = text1_words & text2_words
        union = text1_words | text2_words

        union.empty? ? 0 : (intersection.size.to_f / union.size)
      end
    end

    # Advanced date/time utilities
    class DateTimeUtils
      def self.business_days_between(start_date, end_date)
        return 0 if start_date > end_date

        business_days = 0
        current_date = start_date

        while current_date <= end_date
          business_days += 1 unless weekend?(current_date)
          current_date += 1
        end

        business_days
      end

      def self.add_business_days(date, days)
        result_date = date.dup
        added_days = 0

        while added_days < days
          result_date += 1
          unless weekend?(result_date)
            added_days += 1
          end
        end

        result_date
      end

      def self.quarter(date)
        (date.month - 1) / 3 + 1
      end

      def self.week_of_month(date)
        first_day_of_month = Date.new(date.year, date.month, 1)
        week_start = first_day_of_month - first_day_of_month.wday
        ((date - week_start) / 7).to_i + 1
      end

      def self.days_in_month(year, month)
        Date.new(year, month, -1).day
      end

      def self.iso_week_number(date)
        date.strftime('%V').to_i
      end

      def self.parse_flexible_date(date_string)
        # Try various date formats
        formats = [
          '%Y-%m-%d',
          '%m/%d/%Y',
          '%d/%m/%Y',
          '%Y/%m/%d',
          '%B %d, %Y',
          '%d %B %Y',
          '%Y-%m-%d %H:%M:%S',
          '%Y-%m-%dT%H:%M:%S'
        ]

        formats.each do |format|
          begin
            return DateTime.strptime(date_string, format)
          rescue ArgumentError
            next
          end
        end

        # Try natural language parsing
        case date_string.downcase
        when 'today'
          DateTime.now
        when 'yesterday'
          DateTime.now - 1
        when 'tomorrow'
          DateTime.now + 1
        else
          nil
        end
      end

      def self.relative_time(from_time, to_time = Time.now)
        diff_seconds = (to_time - from_time).to_i

        case diff_seconds.abs
        when 0..59
          "#{diff_seconds.abs} seconds ago"
        when 60..3599
          minutes = (diff_seconds / 60).abs
          "#{minutes} minute#{minutes == 1 ? '' : 's'} ago"
        when 3600..86399
          hours = (diff_seconds / 3600).abs
          "#{hours} hour#{hours == 1 ? '' : 's'} ago"
        when 86400..604799
          days = (diff_seconds / 86400).abs
          "#{days} day#{days == 1 ? '' : 's'} ago"
        else
          from_time.strftime('%B %d, %Y')
        end
      end

      private

      def self.weekend?(date)
        date.saturday? || date.sunday?
      end
    end

    # Configuration validator
    class ConfigValidator
      def initialize(schema)
        @schema = schema
      end

      def validate(config)
        errors = []

        @schema.each do |key, rules|
          value = config[key]

          if rules[:required] && value.nil?
            errors << "#{key} is required"
            next
          end

          next if value.nil? && !rules[:required]

          validate_type(value, rules[:type], key, errors)
          validate_range(value, rules[:range], key, errors)
          validate_format(value, rules[:format], key, errors)
          validate_options(value, rules[:options], key, errors)
        end

        errors
      end

      private

      def validate_type(value, expected_type, key, errors)
        return unless expected_type

        case expected_type
        when :string
          errors << "#{key} must be a string" unless value.is_a?(String)
        when :integer
          errors << "#{key} must be an integer" unless value.is_a?(Integer)
        when :float
          errors << "#{key} must be a float" unless value.is_a?(Float) || value.is_a?(Integer)
        when :boolean
          errors << "#{key} must be true or false" unless [true, false].include?(value)
        when :array
          errors << "#{key} must be an array" unless value.is_a?(Array)
        when :hash
          errors << "#{key} must be a hash" unless value.is_a?(Hash)
        end
      end

      def validate_range(value, range, key, errors)
        return unless range && (value.is_a?(Integer) || value.is_a?(Float))

        if range[:min] && value < range[:min]
          errors << "#{key} must be at least #{range[:min]}"
        end

        if range[:max] && value > range[:max]
          errors << "#{key} must be at most #{range[:max]}"
        end
      end

      def validate_format(value, format, key, errors)
        return unless format && value.is_a?(String)

        case format
        when :email
          unless value.match?(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i)
            errors << "#{key} must be a valid email address"
          end
        when :url
          unless value.match?(%r{\Ahttps?://[^\s<>"{}|\\^`\[\]]+\z})
            errors << "#{key} must be a valid URL"
          end
        when :phone
          unless value.match?(/^\+?[\d\s\-\(\)]+$/)
            errors << "#{key} must be a valid phone number"
          end
        end
      end

      def validate_options(value, options, key, errors)
        return unless options && options.is_a?(Array)

        unless options.include?(value)
          errors << "#{key} must be one of: #{options.join(', ')}"
        end
      end
    end

    # Data transformation utilities
    class DataTransformer
      def self.flatten_hash(hash, prefix = '')
        flattened = {}

        hash.each do |key, value|
          new_key = prefix.empty? ? key.to_s : "#{prefix}.#{key}"

          if value.is_a?(Hash)
            flattened.merge!(flatten_hash(value, new_key))
          elsif value.is_a?(Array)
            value.each_with_index do |item, index|
              if item.is_a?(Hash)
                flattened.merge!(flatten_hash(item, "#{new_key}[#{index}]"))
              else
                flattened["#{new_key}[#{index}]"] = item
              end
            end
          else
            flattened[new_key] = value
          end
        end

        flattened
      end

      def self.unflatten_hash(flattened_hash)
        result = {}

        flattened_hash.each do |key, value|
          keys = parse_nested_key(key)
          set_nested_value(result, keys, value)
        end

        result
      end

      def self.transform_keys(hash, &block)
        result = {}

        hash.each do |key, value|
          new_key = block.call(key)

          if value.is_a?(Hash)
            result[new_key] = transform_keys(value, &block)
          elsif value.is_a?(Array)
            result[new_key] = value.map do |item|
              item.is_a?(Hash) ? transform_keys(item, &block) : item
            end
          else
            result[new_key] = value
          end
        end

        result
      end

      def self.deep_merge(hash1, hash2)
        result = hash1.dup

        hash2.each do |key, value|
          if result.key?(key) && result[key].is_a?(Hash) && value.is_a?(Hash)
            result[key] = deep_merge(result[key], value)
          else
            result[key] = value
          end
        end

        result
      end

      def self.filter_by_keys(hash, keys_to_keep)
        hash.select { |key, _| keys_to_keep.include?(key) }
      end

      def self.reject_by_keys(hash, keys_to_reject)
        hash.reject { |key, _| keys_to_reject.include?(key) }
      end

      private

      def self.parse_nested_key(key)
        key.scan(/[^\[\].]+|\[[^\]]*\]/).map do |part|
          part.start_with?('[') ? part[1..-2] : part
        end
      end

      def self.set_nested_value(hash, keys, value)
        current = hash

        keys[0..-2].each do |key|
          current[key] ||= {}
          current = current[key]
        end

        current[keys.last] = value
      end
    end

    # Performance profiler
    class PerformanceProfiler
      def initialize
        @timers = {}
        @counters = {}
        @gauges = {}
      end

      def time(label, &block)
        start_time = Time.now
        result = block.call
        end_time = Time.now

        duration = end_time - start_time
        @timers[label] ||= []
        @timers[label] << duration

        puts "TIMER: #{label} took #{duration.round(4)}s"
        result
      end

      def increment_counter(label, amount = 1)
        @counters[label] ||= 0
        @counters[label] += amount
      end

      def set_gauge(label, value)
        @gauges[label] = value
      end

      def measure_memory_usage(label, &block)
        before = memory_usage
        result = block.call
        after = memory_usage

        puts "MEMORY: #{label} - Before: #{before}MB, After: #{after}MB, Diff: #{(after - before).round(2)}MB"
        result
      end

      def benchmark(label, iterations = 1000, &block)
        times = []

        iterations.times do
          start_time = Time.now
          block.call
          end_time = Time.now
          times << (end_time - start_time)
        end

        avg_time = times.sum / times.size
        min_time = times.min
        max_time = times.max

        puts "BENCHMARK: #{label}"
        puts "  Iterations: #{iterations}"
        puts "  Average: #{avg_time.round(6)}s"
        puts "  Min: #{min_time.round(6)}s"
        puts "  Max: #{max_time.round(6)}s"
        puts "  Total: #{times.sum.round(4)}s"
      end

      def report
        {
          timers: @timers.transform_values do |times|
            {
              count: times.size,
              total: times.sum,
              average: times.sum / times.size,
              min: times.min,
              max: times.max
            }
          end,
          counters: @counters,
          gauges: @gauges
        }
      end

      private

      def memory_usage
        # This is a simplified implementation
        # In a real Ruby application, you'd use a gem like 'memory_profiler'
        `ps -o rss= -p #{Process.pid}`.to_i / 1024.0 rescue 0
      end
    end
  end
end
