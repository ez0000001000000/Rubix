# Utility libraries and helpers
# This file contains various utility classes and helper methods

module Rubix
  module Utils
    # File management utilities
    class FileManager
      def self.read_file(path, encoding = 'utf-8')
        File.read(path, encoding: encoding)
      rescue => e
        raise Rubix::Error, "Failed to read file #{path}: #{e.message}"
      end

      def self.write_file(path, content, encoding = 'utf-8')
        create_directory(File.dirname(path))
        File.write(path, content, encoding: encoding)
      rescue => e
        raise Rubix::Error, "Failed to write file #{path}: #{e.message}"
      end

      def self.append_file(path, content, encoding = 'utf-8')
        create_directory(File.dirname(path))
        File.open(path, 'a', encoding: encoding) { |f| f.write(content) }
      rescue => e
        raise Rubix::Error, "Failed to append to file #{path}: #{e.message}"
      end

      def self.copy_file(source, destination)
        create_directory(File.dirname(destination))
        FileUtils.cp(source, destination)
      rescue => e
        raise Rubix::Error, "Failed to copy file from #{source} to #{destination}: #{e.message}"
      end

      def self.move_file(source, destination)
        create_directory(File.dirname(destination))
        FileUtils.mv(source, destination)
      rescue => e
        raise Rubix::Error, "Failed to move file from #{source} to #{destination}: #{e.message}"
      end

      def self.delete_file(path)
        File.delete(path) if File.exist?(path)
      rescue => e
        raise Rubix::Error, "Failed to delete file #{path}: #{e.message}"
      end

      def self.file_exists?(path)
        File.exist?(path)
      end

      def self.directory_exists?(path)
        Dir.exist?(path)
      end

      def self.create_directory(path)
        FileUtils.mkdir_p(path)
      rescue => e
        raise Rubix::Error, "Failed to create directory #{path}: #{e.message}"
      end

      def self.delete_directory(path)
        FileUtils.rm_rf(path) if Dir.exist?(path)
      rescue => e
        raise Rubix::Error, "Failed to delete directory #{path}: #{e.message}"
      end

      def self.list_files(path, pattern = '*')
        Dir.glob(File.join(path, pattern))
      end

      def self.list_directories(path)
        Dir.glob(File.join(path, '*/')).map { |d| d.chomp('/') }
      end

      def self.file_size(path)
        File.size(path) if File.exist?(path)
      end

      def self.file_modified_time(path)
        File.mtime(path) if File.exist?(path)
      end

      def self.touch_file(path)
        FileUtils.touch(path)
      rescue => e
        raise Rubix::Error, "Failed to touch file #{path}: #{e.message}"
      end

      def self.read_yaml_file(path)
        require 'yaml'
        YAML.load_file(path)
      rescue => e
        raise Rubix::Error, "Failed to read YAML file #{path}: #{e.message}"
      end

      def self.write_yaml_file(path, data)
        require 'yaml'
        create_directory(File.dirname(path))
        File.write(path, data.to_yaml)
      rescue => e
        raise Rubix::Error, "Failed to write YAML file #{path}: #{e.message}"
      end

      def self.read_json_file(path)
        require 'json'
        JSON.parse(File.read(path), symbolize_names: true)
      rescue => e
        raise Rubix::Error, "Failed to read JSON file #{path}: #{e.message}"
      end

      def self.write_json_file(path, data, pretty = true)
        require 'json'
        create_directory(File.dirname(path))
        json_content = pretty ? JSON.pretty_generate(data) : data.to_json
        File.write(path, json_content)
      rescue => e
        raise Rubix::Error, "Failed to write JSON file #{path}: #{e.message}"
      end

      def self.temp_file(content = nil, extension = nil)
        file = Tempfile.new(['rubix', extension])
        file.write(content) if content
        file.close
        file
      end

      def self.temp_directory
        Dir.mktmpdir('rubix')
      end

      def self.backup_file(path, backup_suffix = '.backup')
        backup_path = path + backup_suffix
        copy_file(path, backup_path) if file_exists?(path)
        backup_path
      end

      def self.restore_file(path, backup_suffix = '.backup')
        backup_path = path + backup_suffix
        move_file(backup_path, path) if file_exists?(backup_path)
      end
    end

    # HTTP client utilities
    class HTTPClient
      attr_reader :base_url, :headers, :timeout

      def initialize(base_url = nil, options = {})
        @base_url = base_url
        @headers = options[:headers] || { 'User-Agent' => 'Rubix HTTP Client' }
        @timeout = options[:timeout] || 30
        @ssl_verify = options.fetch(:ssl_verify, true)
      end

      def get(path, params = {}, headers = {})
        url = build_url(path, params)
        request = Net::HTTP::Get.new(url, @headers.merge(headers))
        execute_request(url, request)
      end

      def post(path, data = {}, headers = {})
        url = build_url(path)
        request = Net::HTTP::Post.new(url, @headers.merge(headers))
        set_request_body(request, data)
        execute_request(url, request)
      end

      def put(path, data = {}, headers = {})
        url = build_url(path)
        request = Net::HTTP::Put.new(url, @headers.merge(headers))
        set_request_body(request, data)
        execute_request(url, request)
      end

      def patch(path, data = {}, headers = {})
        url = build_url(path)
        request = Net::HTTP::Patch.new(url, @headers.merge(headers))
        set_request_body(request, data)
        execute_request(url, request)
      end

      def delete(path, headers = {})
        url = build_url(path)
        request = Net::HTTP::Delete.new(url, @headers.merge(headers))
        execute_request(url, request)
      end

      def head(path, headers = {})
        url = build_url(path)
        request = Net::HTTP::Head.new(url, @headers.merge(headers))
        execute_request(url, request)
      end

      def download(url, destination_path)
        uri = URI(url)
        response = Net::HTTP.get_response(uri)

        if response.is_a?(Net::HTTPSuccess)
          FileManager.write_file(destination_path, response.body)
          true
        else
          false
        end
      rescue => e
        raise Rubix::Error, "Failed to download #{url}: #{e.message}"
      end

      private

      def build_url(path, params = {})
        url = @base_url ? URI.join(@base_url, path).to_s : path
        uri = URI(url)

        if params.any?
          query = URI.encode_www_form(params)
          uri.query = uri.query ? "#{uri.query}&#{query}" : query
        end

        uri.to_s
      end

      def execute_request(url, request)
        uri = URI(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.verify_mode = @ssl_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        http.read_timeout = @timeout

        response = http.request(request)
        HTTPResponse.new(response)
      rescue => e
        raise Rubix::Error, "HTTP request failed: #{e.message}"
      end

      def set_request_body(request, data)
        case data
        when Hash
          request.set_form_data(data)
          request['Content-Type'] = 'application/x-www-form-urlencoded'
        when String
          request.body = data
        else
          request.body = data.to_json
          request['Content-Type'] = 'application/json'
        end
      end

      class HTTPResponse
        attr_reader :status, :headers, :body, :success

        def initialize(net_http_response)
          @status = net_http_response.code.to_i
          @headers = net_http_response.to_hash
          @body = net_http_response.body
          @success = net_http_response.is_a?(Net::HTTPSuccess)
        end

        def json
          JSON.parse(@body, symbolize_names: true) if @body
        rescue JSON::ParserError
          nil
        end

        def xml
          require 'nokogiri'
          Nokogiri::XML(@body) if @body
        rescue LoadError
          raise Rubix::Error, "Nokogiri gem required for XML parsing"
        end

        def text
          @body
        end

        def success?
          @success
        end

        def redirect?
          @status >= 300 && @status < 400
        end

        def error?
          @status >= 400
        end

        def server_error?
          @status >= 500
        end

        def client_error?
          @status >= 400 && @status < 500
        end

        def not_found?
          @status == 404
        end

        def unauthorized?
          @status == 401
        end

        def forbidden?
          @status == 403
        end

        def bad_request?
          @status == 400
        end

        def internal_server_error?
          @status == 500
        end
      end
    end

    # Cache utilities
    class CacheHelper
      def self.generate_key(*parts)
        parts.map(&:to_s).join(':')
      end

      def self.generate_versioned_key(key, version)
        "#{key}:v#{version}"
      end

      def self.generate_namespaced_key(namespace, key)
        "#{namespace}:#{key}"
      end

      def self.compress_value(value)
        Rubix::Utils.compress(value.to_json)
      end

      def self.decompress_value(value)
        decompressed = Rubix::Utils.decompress(value)
        JSON.parse(decompressed, symbolize_names: true)
      rescue JSON::ParserError
        decompressed
      end

      def self.generate_ttl(expiry_time)
        if expiry_time.is_a?(Time)
          (expiry_time - Time.now).to_i
        else
          expiry_time.to_i
        end
      end
    end

    # String manipulation utilities
    class StringHelper
      def self.truncate(text, length = 100, omission = '...')
        return text if text.length <= length
        text[0...(length - omission.length)] + omission
      end

      def self.strip_html(text)
        text.gsub(/<[^>]*>/, '')
      end

      def self.strip_tags(text)
        strip_html(text)
      end

      def self.escape_html(text)
        text.gsub(/[&<>"']/) do |match|
          case match
          when '&' then '&amp;'
          when '<' then '&lt;'
          when '>' then '&gt;'
          when '"' then '&quot;'
          when "'" then '&#x27;'
          end
        end
      end

      def self.unescape_html(text)
        text.gsub(/&(amp|lt|gt|quot|#x27);/) do |match|
          case match
          when '&amp;' then '&'
          when '&lt;' then '<'
          when '&gt;' then '>'
          when '&quot;' then '"'
          when '&#x27;' then "'"
          end
        end
      end

      def self.slugify(text)
        text.downcase.gsub(/[^a-z0-9\s-]/, '').strip.gsub(/\s+/, '-').gsub(/-+/, '-')
      end

      def self.parameterize(text, separator = '-')
        text.downcase.gsub(/[^a-z0-9\s#{separator}]/, '').strip.gsub(/\s+/, separator).gsub(/#{separator}+/, separator)
      end

      def self.titleize(text)
        text.split.map(&:capitalize).join(' ')
      end

      def self.humanize(text)
        text.to_s.gsub(/_/, ' ').capitalize
      end

      def self.constantize(text)
        text.split('_').map(&:capitalize).join
      end

      def self.underscore(text)
        text.gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').
             gsub(/([a-z\d])([A-Z])/,'\1_\2').
             tr("-", "_").
             downcase
      end

      def self.camelize(text)
        text.split('_').map(&:capitalize).join
      end

      def self.pluralize(word)
        case word
        when /s$/, /sh$/, /ch$/, /x$/, /z$/ then word + 'es'
        when /y$/ then word.sub(/y$/, 'ies')
        when /f$/ then word.sub(/f$/, 'ves')
        when /fe$/ then word.sub(/fe$/, 'ves')
        else word + 's'
        end
      end

      def self.singularize(word)
        case word
        when /ies$/ then word.sub(/ies$/, 'y')
        when /ves$/ then word.sub(/ves$/, 'f')
        when /es$/ then word.sub(/es$/, '')
        when /s$/ then word.sub(/s$/, '')
        else word
        end
      end

      def self.extract_email_addresses(text)
        text.scan(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/)
      end

      def self.extract_urls(text)
        text.scan(%r{https?://[^\s<>"']+})
      end

      def self.extract_hashtags(text)
        text.scan(/#\w+/)
      end

      def self.extract_mentions(text)
        text.scan(/@\w+/)
      end

      def self.remove_accents(text)
        text.tr('áéíóúÁÉÍÓÚ', 'aeiouAEIOU')
      end

      def self.normalize_whitespace(text)
        text.gsub(/\s+/, ' ').strip
      end

      def self.word_count(text)
        text.split.size
      end

      def self.character_count(text)
        text.length
      end

      def self.line_count(text)
        text.lines.size
      end

      def self.average_word_length(text)
        words = text.split
        return 0 if words.empty?
        words.sum(&:length) / words.size.to_f
      end
    end

    # Array manipulation utilities
    class ArrayHelper
      def self.compact_blank(array)
        array.reject(&:blank?)
      end

      def self.uniq_by(array, &block)
        array.uniq { |item| block.call(item) }
      end

      def self.group_by_size(array, size)
        array.each_slice(size).to_a
      end

      def self.rotate_left(array, positions = 1)
        positions.times { array.push(array.shift) }
        array
      end

      def self.rotate_right(array, positions = 1)
        positions.times { array.unshift(array.pop) }
        array
      end

      def self.shuffle(array)
        array.sort_by { rand }
      end

      def self.random_sample(array, count = 1)
        shuffle(array).take(count)
      end

      def self.remove_duplicates(array)
        array.uniq
      end

      def self.intersection(*arrays)
        arrays.inject(:&)
      end

      def self.union(*arrays)
        arrays.inject(:|)
      end

      def self.difference(array1, array2)
        array1 - array2
      end

      def self.symmetric_difference(array1, array2)
        (array1 - array2) | (array2 - array1)
      end

      def self.cartesian_product(*arrays)
        arrays.inject([[]]) do |result, array|
          result.product(array).map(&:flatten)
        end
      end

      def self.permutations(array, size = nil)
        size ||= array.size
        array.permutation(size).to_a
      end

      def self.combinations(array, size)
        array.combination(size).to_a
      end

      def self.power_set(array)
        (0..array.size).flat_map { |n| array.combination(n).to_a }
      end

      def self.longest_common_prefix(*arrays)
        return '' if arrays.empty?
        return arrays.first.join if arrays.size == 1

        min_length = arrays.map(&:size).min
        prefix = []

        min_length.times do |i|
          char = arrays.first[i]
          break unless arrays.all? { |arr| arr[i] == char }
          prefix << char
        end

        prefix
      end

      def self.longest_common_suffix(*arrays)
        arrays.map(&:reverse).then { |reversed| longest_common_prefix(*reversed) }.reverse
      end

      def self.frequency_hash(array)
        array.each_with_object(Hash.new(0)) { |item, hash| hash[item] += 1 }
      end

      def self.mode(array)
        freq = frequency_hash(array)
        max_freq = freq.values.max
        freq.select { |_, count| count == max_freq }.keys
      end

      def self.median(array)
        sorted = array.sort
        len = sorted.length
        return nil if len.zero?

        if len.odd?
          sorted[len / 2]
        else
          (sorted[len / 2 - 1] + sorted[len / 2]) / 2.0
        end
      end

      def self.mean(array)
        return nil if array.empty?
        array.sum / array.size.to_f
      end

      def self.variance(array)
        return nil if array.size < 2
        avg = mean(array)
        sum_of_squares = array.sum { |x| (x - avg) ** 2 }
        sum_of_squares / (array.size - 1)
      end

      def self.standard_deviation(array)
        Math.sqrt(variance(array) || 0)
      end
    end

    # Hash manipulation utilities
    class HashHelper
      def self.deep_symbolize_keys(hash)
        hash.each_with_object({}) do |(k, v), h|
          h[k.to_sym] = case v
                        when Hash then deep_symbolize_keys(v)
                        when Array then v.map { |e| e.is_a?(Hash) ? deep_symbolize_keys(e) : e }
                        else v
                        end
        end
      end

      def self.deep_stringify_keys(hash)
        hash.each_with_object({}) do |(k, v), h|
          h[k.to_s] = case v
                      when Hash then deep_stringify_keys(v)
                      when Array then v.map { |e| e.is_a?(Hash) ? deep_stringify_keys(e) : e }
                      else v
                      end
        end
      end

      def self.flatten_keys(hash, prefix = '')
        hash.each_with_object({}) do |(k, v), h|
          key = prefix.empty? ? k.to_s : "#{prefix}.#{k}"
          if v.is_a?(Hash)
            h.merge!(flatten_keys(v, key))
          else
            h[key] = v
          end
        end
      end

      def self.unflatten_keys(hash)
        hash.each_with_object({}) do |(k, v), h|
          keys = k.to_s.split('.')
          current = h

          keys[0..-2].each do |key|
            current[key] ||= {}
            current = current[key]
          end

          current[keys.last] = v
        end
      end

      def self.compact(hash)
        hash.reject { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }
      end

      def self.slice(hash, *keys)
        hash.select { |k, _| keys.include?(k) }
      end

      def self.except(hash, *keys)
        hash.reject { |k, _| keys.include?(k) }
      end

      def self.defaults(hash, defaults)
        defaults.merge(hash)
      end

      def self.reverse_merge(hash, other)
        other.merge(hash)
      end

      def self.reverse_merge!(hash, other)
        hash.merge!(other) { |_, old_val, _| old_val }
      end

      def self.transform_keys(hash, &block)
        hash.each_with_object({}) do |(k, v), h|
          h[block.call(k)] = v
        end
      end

      def self.transform_values(hash, &block)
        hash.each_with_object({}) do |(k, v), h|
          h[k] = block.call(v)
        end
      end

      def self.deep_transform_keys(hash, &block)
        hash.each_with_object({}) do |(k, v), h|
          new_key = block.call(k)
          h[new_key] = case v
                       when Hash then deep_transform_keys(v, &block)
                       when Array then v.map { |e| e.is_a?(Hash) ? deep_transform_keys(e, &block) : e }
                       else v
                       end
        end
      end

      def self.deep_transform_values(hash, &block)
        hash.each_with_object({}) do |(k, v), h|
          h[k] = case v
                 when Hash then deep_transform_values(v, &block)
                 when Array then v.map { |e| e.is_a?(Hash) ? deep_transform_values(e, &block) : block.call(e) }
                 else block.call(v)
                 end
        end
      end

      def self.diff(hash1, hash2)
        added = hash2.except(*hash1.keys)
        removed = hash1.except(*hash2.keys)
        changed = {}

        (hash1.keys & hash2.keys).each do |key|
          if hash1[key] != hash2[key]
            changed[key] = [hash1[key], hash2[key]]
          end
        end

        { added: added, removed: removed, changed: changed }
      end

      def self.merge_recursive(hash1, hash2)
        hash1.merge(hash2) do |key, old_val, new_val|
          if old_val.is_a?(Hash) && new_val.is_a?(Hash)
            merge_recursive(old_val, new_val)
          else
            new_val
          end
        end
      end

      def self.sort_by_keys(hash)
        hash.sort.to_h
      end

      def self.sort_by_values(hash)
        hash.sort_by { |_, v| v }.to_h
      end

      def self.group_by_value_type(hash)
        hash.group_by { |_, v| v.class }
      end

      def self.pick_random(hash, count = 1)
        hash.to_a.sample(count).to_h
      end

      def self.invert_with_duplicates(hash)
        hash.each_with_object({}) do |(k, v), h|
          h[v] ||= []
          h[v] << k
        end
      end
    end

    # Date and time utilities
    class DateTimeHelper
      def self.parse_date(date_string, format = nil)
        if format
          Date.strptime(date_string, format)
        else
          Date.parse(date_string)
        end
      rescue ArgumentError
        nil
      end

      def self.parse_time(time_string, format = nil)
        if format
          Time.strptime(time_string, format)
        else
          Time.parse(time_string)
        end
      rescue ArgumentError
        nil
      end

      def self.format_date(date, format = '%Y-%m-%d')
        date.strftime(format)
      end

      def self.format_time(time, format = '%Y-%m-%d %H:%M:%S')
        time.strftime(format)
      end

      def self.relative_time(time, now = Time.now)
        diff = (now - time).to_i

        case diff
        when 0..59 then "#{diff} seconds ago"
        when 60..3599 then "#{(diff / 60).to_i} minutes ago"
        when 3600..86399 then "#{(diff / 3600).to_i} hours ago"
        when 86400..604799 then "#{(diff / 86400).to_i} days ago"
        else format_time(time)
        end
      end

      def self.time_ago_in_words(time, now = Time.now)
        relative_time(time, now)
      end

      def self.business_days_between(start_date, end_date)
        (start_date..end_date).count { |date| !weekend?(date) }
      end

      def self.weekend?(date)
        date.saturday? || date.sunday?
      end

      def self.workday?(date)
        !weekend?(date)
      end

      def self.add_business_days(date, days)
        result = date
        days.times do
          result = result.next_day
          result = result.next_day if weekend?(result)
        end
        result
      end

      def self.beginning_of_week(date, start_day = :monday)
        days_to_subtract = case start_day
                           when :monday then date.wday - 1
                           when :sunday then date.wday
                           else 0
                           end
        date - days_to_subtract
      end

      def self.end_of_week(date, start_day = :monday)
        beginning_of_week(date, start_day) + 6
      end

      def self.beginning_of_month(date)
        Date.new(date.year, date.month, 1)
      end

      def self.end_of_month(date)
        Date.new(date.year, date.month, -1)
      end

      def self.beginning_of_quarter(date)
        quarter_start_month = ((date.month - 1) / 3) * 3 + 1
        Date.new(date.year, quarter_start_month, 1)
      end

      def self.end_of_quarter(date)
        quarter_end_month = ((date.month - 1) / 3 + 1) * 3
        Date.new(date.year, quarter_end_month, -1)
      end

      def self.beginning_of_year(date)
        Date.new(date.year, 1, 1)
      end

      def self.end_of_year(date)
        Date.new(date.year, 12, 31)
      end

      def self.days_in_month(year, month)
        Date.new(year, month, -1).day
      end

      def self.days_in_year(year)
        Date.new(year, 12, 31).yday
      end

      def self.leap_year?(year)
        Date.new(year).leap?
      end

      def self.iso_week_number(date)
        date.cweek
      end

      def self.day_of_year(date)
        date.yday
      end

      def self.week_of_year(date)
        date.cweek
      end

      def self.quarter(date)
        (date.month - 1) / 3 + 1
      end

      def self.age(birth_date, current_date = Date.today)
        current_date.year - birth_date.year - (current_date.yday < birth_date.yday ? 1 : 0)
      end
    end

    # Random data generation utilities
    class RandomHelper
      def self.uuid
        SecureRandom.uuid
      end

      def self.token(length = 32)
        SecureRandom.hex(length)
      end

      def self.password(length = 12, options = {})
        chars = ''
        chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if options.fetch(:uppercase, true)
        chars += 'abcdefghijklmnopqrstuvwxyz' if options.fetch(:lowercase, true)
        chars += '0123456789' if options.fetch(:numbers, true)
        chars += '!@#$%^&*()_+-=[]{}|;:,.<>?' if options.fetch(:symbols, true)

        (0...length).map { chars[rand(chars.length)] }.join
      end

      def self.email(domain = 'example.com')
        "#{random_string(8)}@#{domain}"
      end

      def self.name
        "#{random_string(4, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')} #{random_string(6, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"
      end

      def self.first_name
        random_string(6, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
      end

      def self.last_name
        random_string(8, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
      end

      def self.phone_number
        "+1-#{rand(100..999)}-#{rand(100..999)}-#{rand(1000..9999)}"
      end

      def self.address
        "#{rand(1000..9999)} #{random_string(10)} Street"
      end

      def self.city
        random_string(8, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
      end

      def self.zip_code
        "#{rand(10000..99999)}"
      end

      def self.ip_address
        "#{rand(1..255)}.#{rand(0..255)}.#{rand(0..255)}.#{rand(0..255)}"
      end

      def self.mac_address
        6.times.map { rand(256).to_s(16).rjust(2, '0') }.join(':')
      end

      def self.url(domain = nil)
        domain ||= "#{random_string(8)}.com"
        "https://#{domain}/#{random_string(10)}"
      end

      def self.paragraph(sentences = 3)
        sentences.times.map { sentence }.join(' ')
      end

      def self.sentences(count = 1)
        count.times.map { sentence }.join(' ')
      end

      def self.sentence
        words = rand(5..15).times.map { word }
        words.first.capitalize!
        words.join(' ') + '.'
      end

      def self.words(count = 1)
        count.times.map { word }.join(' ')
      end

      def self.word
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        length = rand(3..8)
        result = ''

        length.times do |i|
          result += if i.even?
                      consonants[rand(consonants.length)]
                    else
                      vowels[rand(vowels.length)]
                    end
        end

        result
      end

      def self.number(min = 0, max = 100)
        rand(min..max)
      end

      def self.float(min = 0.0, max = 100.0)
        rand * (max - min) + min
      end

      def self.boolean
        rand(2) == 1
      end

      def self.date(start_date = Date.new(2000, 1, 1), end_date = Date.today)
        random_days = rand((end_date - start_date).to_i)
        start_date + random_days
      end

      def self.time
        Time.at(rand(Time.now.to_i))
      end

      def self.array(size = 5, generator = :number)
        size.times.map { send(generator) }
      end

      def self.hash(keys = 5, generator = :word)
        keys.times.each_with_object({}) do |_, hash|
          hash[send(generator)] = send(generator)
        end
      end

      def self.json(depth = 2)
        generate_json_value(depth).to_json
      end

      def self.color
        "##{rand(16777216).to_s(16).rjust(6, '0')}"
      end

      def self.hex_color
        color
      end

      def self.rgb_color
        [rand(256), rand(256), rand(256)]
      end

      private

      def self.random_string(length, charset = 'abcdefghijklmnopqrstuvwxyz0123456789')
        length.times.map { charset[rand(charset.length)] }.join
      end

      def self.generate_json_value(depth)
        case rand(4)
        when 0 then rand(1000)
        when 1 then random_string(8)
        when 2 then boolean
        when 3 then depth > 0 ? hash(3, :generate_json_value) : random_string(5)
        end
      end

      def self.method_missing(method_name, *args)
        if method_name.to_s.start_with?('random_')
          generator = method_name.to_s.sub('random_', '').to_sym
          if respond_to?(generator)
            send(generator, *args)
          else
            super
          end
        else
          super
        end
      end
    end

    # System utilities
    class SystemHelper
      def self.cpu_count
        if RUBY_PLATFORM =~ /linux/
          File.read('/proc/cpuinfo').scan(/^processor\s*:/).size
        elsif RUBY_PLATFORM =~ /darwin/
          `sysctl -n hw.ncpu`.to_i
        else
          1
        end
      rescue
        1
      end

      def self.memory_usage
        if RUBY_PLATFORM =~ /linux/
          `ps -o rss= -p #{Process.pid}`.to_i * 1024
        else
          0
        end
      rescue
        0
      end

      def self.process_info(pid = Process.pid)
        {
          pid: pid,
          memory: memory_usage,
          cpu_count: cpu_count,
          ruby_version: RUBY_VERSION,
          platform: RUBY_PLATFORM,
          start_time: Time.now - Process.times.utime
        }
      end

      def self.available_memory
        if RUBY_PLATFORM =~ /linux/
          mem_info = File.read('/proc/meminfo')
          mem_total = mem_info.match(/MemTotal:\s+(\d+)\s+kB/)&.captures&.first&.to_i
          mem_available = mem_info.match(/MemAvailable:\s+(\d+)\s+kB/)&.captures&.first&.to_i
          { total: mem_total * 1024, available: mem_available * 1024 }
        else
          { total: 0, available: 0 }
        end
      rescue
        { total: 0, available: 0 }
      end

      def self.disk_usage(path = '.')
        stat = File.stat(path)
        {
          total: stat.size,
          used: stat.blocks * 512,
          free: 0 # Simplified
        }
      rescue
        { total: 0, used: 0, free: 0 }
      end

      def self.load_average
        if RUBY_PLATFORM =~ /linux/
          loadavg = File.read('/proc/loadavg').split
          loadavg[0..2].map(&:to_f)
        else
          [0.0, 0.0, 0.0]
        end
      rescue
        [0.0, 0.0, 0.0]
      end

      def self.uptime
        if RUBY_PLATFORM =~ /linux/
          File.read('/proc/uptime').split.first.to_f
        else
          0.0
        end
      rescue
        0.0
      end

      def self.network_interfaces
        if RUBY_PLATFORM =~ /linux/
          interfaces = {}
          Dir.glob('/sys/class/net/*').each do |iface_dir|
            iface_name = File.basename(iface_dir)
            addresses_file = File.join(iface_dir, 'address')
            if File.exist?(addresses_file)
              mac = File.read(addresses_file).strip
              interfaces[iface_name] = { mac: mac }
            end
          end
          interfaces
        else
          {}
        end
      rescue
        {}
      end

      def self.environment_variables(pattern = nil)
        if pattern
          ENV.select { |k, _| k =~ pattern }
        else
          ENV.to_h
        end
      end

      def self.ruby_gems
        Gem.loaded_specs.keys
      rescue
        []
      end

      def self.ruby_load_path
        $LOAD_PATH.dup
      end

      def self.garbage_collect
        GC.start
        GC.stat
      end

      def self.object_count
        ObjectSpace.count_objects
      end

      def self.thread_count
        Thread.list.size
      end

      def self.fiber_count
        Fiber.list.size
      rescue
        0
      end
    end
  end
end
