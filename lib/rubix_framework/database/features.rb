# Advanced database features
# This file contains database seeding, fixtures, and advanced query features

require 'rubygems'
require 'yaml'
require 'json'
require 'csv'
require 'digest'
require 'time'

module Rubix
  module Database
    # Database seeder
    class Seeder
      def initialize(connection)
        @connection = connection
        @seeds_path = 'db/seeds'
        @fixtures_path = 'test/fixtures'
      end

      def run
        load_seed_files
        puts "Database seeded successfully"
      end

      def load_seed_files
        Dir.glob("#{@seeds_path}/*.rb").sort.each do |file|
          load file
        end
      end

      def seed_table(table_name, records)
        records.each do |record|
          insert_record(table_name, record)
        end
      end

      def seed_from_csv(table_name, csv_file)
        CSV.foreach("#{@seeds_path}/#{csv_file}", headers: true) do |row|
          insert_record(table_name, row.to_hash)
        end
      end

      def seed_from_yaml(table_name, yaml_file)
        data = YAML.load_file("#{@seeds_path}/#{yaml_file}")
        seed_table(table_name, data)
      end

      def seed_from_json(table_name, json_file)
        data = JSON.parse(File.read("#{@seeds_path}/#{json_file}"))
        seed_table(table_name, data)
      end

      private

      def insert_record(table_name, record)
        columns = record.keys
        values = record.values
        placeholders = (['?'] * columns.size).join(', ')

        sql = "INSERT INTO #{table_name} (#{columns.join(', ')}) VALUES (#{placeholders})"
        @connection.execute(sql, values)
      end
    end

    # Database fixtures
    class Fixtures
      def initialize(connection)
        @connection = connection
        @fixtures_path = 'test/fixtures'
      end

      def load(fixture_name)
        fixture_file = "#{@fixtures_path}/#{fixture_name}.yml"
        return unless File.exist?(fixture_file)

        data = YAML.load_file(fixture_file)
        table_name = fixture_name.pluralize

        @connection.transaction do
          data.each do |key, record|
            insert_fixture_record(table_name, record)
          end
        end
      end

      def load_all
        Dir.glob("#{@fixtures_path}/*.yml").each do |file|
          fixture_name = File.basename(file, '.yml')
          load(fixture_name)
        end
      end

      def create(fixture_name, records)
        fixture_file = "#{@fixtures_path}/#{fixture_name}.yml"
        FileUtils.mkdir_p(File.dirname(fixture_file))

        fixture_data = {}
        records.each_with_index do |record, index|
          fixture_data["record_#{index + 1}"] = record
        end

        File.write(fixture_file, fixture_data.to_yaml)
      end

      private

      def insert_fixture_record(table_name, record)
        columns = record.keys
        values = record.values
        placeholders = (['?'] * columns.size).join(', ')

        sql = "INSERT INTO #{table_name} (#{columns.join(', ')}) VALUES (#{placeholders})"
        @connection.execute(sql, values)
      end
    end

    # Advanced query features
    class AdvancedQuery
      def initialize(model_class)
        @model_class = model_class
        @query_parts = []
        @joins = []
        @includes = []
        @group_by = []
        @having = []
        @order_by = []
        @limit = nil
        @offset = nil
        @distinct = false
        @select_fields = ['*']
      end

      def select(*fields)
        @select_fields = fields.flatten
        self
      end

      def distinct
        @distinct = true
        self
      end

      def where(conditions)
        @query_parts << { type: :where, conditions: conditions }
        self
      end

      def joins(join_spec)
        @joins << join_spec
        self
      end

      def includes(*associations)
        @includes.concat(associations)
        self
      end

      def group(*fields)
        @group_by.concat(fields)
        self
      end

      def having(conditions)
        @having << conditions
        self
      end

      def order(*fields)
        @order_by.concat(fields)
        self
      end

      def limit(value)
        @limit = value
        self
      end

      def offset(value)
        @offset = value
        self
      end

      def to_sql
        sql = build_select_clause
        sql << build_from_clause
        sql << build_join_clause
        sql << build_where_clause
        sql << build_group_by_clause
        sql << build_having_clause
        sql << build_order_by_clause
        sql << build_limit_offset_clause
        sql
      end

      def execute
        sql = to_sql
        results = @model_class.connection.execute(sql)
        results.map { |row| @model_class.new(row) }
      end

      def count
        original_select = @select_fields
        @select_fields = ['COUNT(*) as count']
        sql = to_sql
        result = @model_class.connection.execute(sql).first
        @select_fields = original_select
        result['count'].to_i
      end

      def exists?
        original_select = @select_fields
        original_limit = @limit
        @select_fields = ['1']
        @limit = 1
        sql = to_sql
        result = @model_class.connection.execute(sql).any?
        @select_fields = original_select
        @limit = original_limit
        result
      end

      def pluck(*fields)
        original_select = @select_fields
        @select_fields = fields
        sql = to_sql
        results = @model_class.connection.execute(sql)
        @select_fields = original_select
        results.map { |row| row.values }
      end

      private

      def build_select_clause
        fields = @distinct ? "DISTINCT #{@select_fields.join(', ')}" : @select_fields.join(', ')
        "SELECT #{fields}"
      end

      def build_from_clause
        " FROM #{@model_class.table_name}"
      end

      def build_join_clause
        return '' if @joins.empty?

        joins_sql = @joins.map do |join|
          case join
          when Hash
            build_join_from_hash(join)
          when String
            join
          end
        end.join(' ')

        " #{joins_sql}"
      end

      def build_join_from_hash(join_hash)
        join_type = join_hash[:type] || 'INNER'
        table = join_hash[:table]
        conditions = join_hash[:on]

        "#{join_type} JOIN #{table} ON #{conditions}"
      end

      def build_where_clause
        return '' if @query_parts.empty?

        where_parts = @query_parts.select { |part| part[:type] == :where }
        return '' if where_parts.empty?

        conditions = where_parts.map { |part| build_conditions(part[:conditions]) }
        " WHERE #{conditions.join(' AND ')}"
      end

      def build_conditions(conditions)
        case conditions
        when Hash
          conditions.map { |key, value| "#{key} = ?" }.join(' AND ')
        when String
          conditions
        end
      end

      def build_group_by_clause
        return '' if @group_by.empty?
        " GROUP BY #{@group_by.join(', ')}"
      end

      def build_having_clause
        return '' if @having.empty?
        " HAVING #{@having.join(' AND ')}"
      end

      def build_order_by_clause
        return '' if @order_by.empty?
        " ORDER BY #{@order_by.join(', ')}"
      end

      def build_limit_offset_clause
        sql = ''
        sql << " LIMIT #{@limit}" if @limit
        sql << " OFFSET #{@offset}" if @offset
        sql
      end
    end

    # Database replication
    class Replication
      def initialize(connection)
        @connection = connection
        @replicas = []
        @master = nil
      end

      def add_replica(config)
        @replicas << ReplicaConnection.new(config)
      end

      def set_master(config)
        @master = MasterConnection.new(config)
      end

      def read(&block)
        replica = @replicas.sample || @master
        replica.execute(&block)
      end

      def write(&block)
        @master.execute(&block)
        sync_to_replicas
      end

      private

      def sync_to_replicas
        # Sync changes to replicas
        # This is a simplified implementation
        @replicas.each do |replica|
          # Sync logic would go here
        end
      end

      class ReplicaConnection
        def initialize(config)
          @config = config
          @connection = establish_connection
        end

        def execute(&block)
          @connection.execute(&block)
        end

        private

        def establish_connection
          # Connection establishment logic
          Connection.new(@config)
        end
      end

      class MasterConnection < ReplicaConnection
        def execute(&block)
          # Master-specific logic (e.g., logging writes)
          super
        end
      end
    end

    # Database sharding
    class Sharding
      def initialize(shard_configs)
        @shards = shard_configs.map { |config| Shard.new(config) }
        @shard_key = :id
      end

      def shard_for(record)
        shard_key_value = record[@shard_key]
        shard_index = shard_key_value % @shards.size
        @shards[shard_index]
      end

      def execute_on_shard(record, &block)
        shard = shard_for(record)
        shard.execute(&block)
      end

      def execute_on_all_shards(&block)
        @shards.each { |shard| shard.execute(&block) }
      end

      def migrate_shards(&block)
        @shards.each do |shard|
          shard.migrate(&block)
        end
      end

      class Shard
        def initialize(config)
          @config = config
          @connection = Connection.new(config)
        end

        def execute(&block)
          @connection.execute(&block)
        end

        def migrate(&block)
          # Migration logic for this shard
          execute(&block)
        end
      end
    end

    # Database backup and restore
    class Backup
      def initialize(connection)
        @connection = connection
        @backup_path = 'db/backups'
        @timestamp_format = '%Y%m%d%H%M%S'
      end

      def create_backup(tables = nil)
        timestamp = Time.now.strftime(@timestamp_format)
        backup_file = "#{@backup_path}/backup_#{timestamp}.sql"

        FileUtils.mkdir_p(@backup_path)

        File.open(backup_file, 'w') do |file|
          write_backup_header(file, timestamp)

          if tables.nil?
            dump_all_tables(file)
          else
            tables.each { |table| dump_table(file, table) }
          end

          write_backup_footer(file)
        end

        compress_backup(backup_file)
        puts "Backup created: #{backup_file}.gz"
        "#{backup_file}.gz"
      end

      def restore_backup(backup_file)
        decompressed_file = decompress_backup(backup_file)

        @connection.transaction do
          File.readlines(decompressed_file).each do |line|
            next if line.strip.empty? || line.start_with?('--')
            @connection.execute(line.strip)
          end
        end

        File.delete(decompressed_file)
        puts "Backup restored: #{backup_file}"
      end

      def list_backups
        Dir.glob("#{@backup_path}/*.gz").sort.reverse
      end

      def cleanup_old_backups(keep_count = 10)
        backups = list_backups
        return if backups.size <= keep_count

        backups[keep_count..-1].each do |backup|
          File.delete(backup)
          puts "Deleted old backup: #{backup}"
        end
      end

      private

      def write_backup_header(file, timestamp)
        file.puts "-- Rubix Database Backup"
        file.puts "-- Created: #{Time.now}"
        file.puts "-- Timestamp: #{timestamp}"
        file.puts
      end

      def dump_all_tables(file)
        tables = get_all_tables
        tables.each { |table| dump_table(file, table) }
      end

      def dump_table(file, table_name)
        file.puts "-- Dumping table: #{table_name}"
        file.puts "DELETE FROM #{table_name};"
        file.puts

        results = @connection.execute("SELECT * FROM #{table_name}")
        results.each do |row|
          values = row.values.map { |value| quote_value(value) }
          file.puts "INSERT INTO #{table_name} VALUES (#{values.join(', ')});"
        end

        file.puts
      end

      def write_backup_footer(file)
        file.puts "-- Backup completed"
        file.puts "-- #{Time.now}"
      end

      def compress_backup(backup_file)
        # Simple compression using gzip
        # In a real implementation, you'd use a proper compression library
        system("gzip #{backup_file}")
      end

      def decompress_backup(backup_file)
        decompressed_file = backup_file.sub('.gz', '')
        system("gunzip -c #{backup_file} > #{decompressed_file}")
        decompressed_file
      end

      def get_all_tables
        # This would vary by database adapter
        case @connection.adapter_name
        when 'sqlite3'
          @connection.execute("SELECT name FROM sqlite_master WHERE type='table'").map { |row| row['name'] }
        else
          []
        end
      end

      def quote_value(value)
        case value
        when String
          "'#{value.gsub("'", "''")}'"
        when NilClass
          'NULL'
        else
          value.to_s
        end
      end
    end

    # Database performance monitoring
    class PerformanceMonitor
      def initialize(connection)
        @connection = connection
        @query_log = []
        @slow_query_threshold = 1000 # milliseconds
        @query_stats = {}
      end

      def log_query(sql, start_time, end_time)
        duration = (end_time - start_time) * 1000 # milliseconds

        query_info = {
          sql: sql,
          duration: duration,
          timestamp: Time.now,
          slow: duration > @slow_query_threshold
        }

        @query_log << query_info
        update_stats(sql, duration)

        if query_info[:slow]
          log_slow_query(query_info)
        end
      end

      def slow_queries(limit = 10)
        @query_log.select { |q| q[:slow] }.last(limit)
      end

      def query_stats
        @query_stats
      end

      def average_query_time
        return 0 if @query_log.empty?
        total_time = @query_log.sum { |q| q[:duration] }
        total_time / @query_log.size
      end

      def query_count
        @query_log.size
      end

      def clear_log
        @query_log.clear
        @query_stats.clear
      end

      def generate_report
        report = {
          total_queries: query_count,
          average_query_time: average_query_time,
          slow_queries_count: slow_queries.size,
          top_slow_queries: slow_queries.first(5),
          query_stats: @query_stats
        }

        report
      end

      private

      def update_stats(sql, duration)
        @query_stats[sql] ||= { count: 0, total_time: 0, avg_time: 0, max_time: 0, min_time: Float::INFINITY }

        stats = @query_stats[sql]
        stats[:count] += 1
        stats[:total_time] += duration
        stats[:avg_time] = stats[:total_time] / stats[:count]
        stats[:max_time] = [stats[:max_time], duration].max
        stats[:min_time] = [stats[:min_time], duration].min
      end

      def log_slow_query(query_info)
        puts "SLOW QUERY: #{query_info[:sql]} (#{query_info[:duration].round(2)}ms)"
      end
    end

    # Database connection pooling
    class ConnectionPool
      def initialize(config)
        @config = config
        @pool_size = config[:pool_size] || 5
        @connections = []
        @available_connections = []
        @mutex = Mutex.new
        @condition = ConditionVariable.new

        initialize_pool
      end

      def with_connection(&block)
        connection = checkout_connection
        begin
          yield connection
        ensure
          checkin_connection(connection)
        end
      end

      def size
        @connections.size
      end

      def available_connections
        @available_connections.size
      end

      def shutdown
        @connections.each do |connection|
          connection.close if connection.respond_to?(:close)
        end
        @connections.clear
        @available_connections.clear
      end

      private

      def initialize_pool
        @pool_size.times do
          connection = Connection.new(@config)
          @connections << connection
          @available_connections << connection
        end
      end

      def checkout_connection
        @mutex.synchronize do
          loop do
            if @available_connections.any?
              return @available_connections.pop
            else
              @condition.wait(@mutex)
            end
          end
        end
      end

      def checkin_connection(connection)
        @mutex.synchronize do
          @available_connections << connection
          @condition.signal
        end
      end
    end

    # Database schema caching
    class SchemaCache
      def initialize(connection)
        @connection = connection
        @cache = {}
        @cache_file = 'db/schema_cache.yml'
        @cache_expiry = 3600 # 1 hour
        load_cache
      end

      def get_table_schema(table_name)
        if cached_schema_expired?(table_name)
          schema = load_table_schema(table_name)
          cache_table_schema(table_name, schema)
          schema
        else
          @cache[table_name][:schema]
        end
      end

      def clear_cache
        @cache.clear
        File.delete(@cache_file) if File.exist?(@cache_file)
      end

      def refresh_cache
        clear_cache
        load_cache
      end

      private

      def load_table_schema(table_name)
        # This would vary by database adapter
        case @connection.adapter_name
        when 'sqlite3'
          columns = @connection.execute("PRAGMA table_info(#{table_name})")
          columns.map do |col|
            {
              name: col['name'],
              type: col['type'],
              nullable: col['notnull'] == 0,
              default: col['dflt_value'],
              primary_key: col['pk'] == 1
            }
          end
        else
          []
        end
      end

      def cache_table_schema(table_name, schema)
        @cache[table_name] = {
          schema: schema,
          cached_at: Time.now.to_i
        }
        save_cache
      end

      def cached_schema_expired?(table_name)
        return true unless @cache.key?(table_name)

        cached_at = @cache[table_name][:cached_at]
        (Time.now.to_i - cached_at) > @cache_expiry
      end

      def load_cache
        return unless File.exist?(@cache_file)

        @cache = YAML.load_file(@cache_file) || {}
      end

      def save_cache
        File.write(@cache_file, @cache.to_yaml)
      end
    end

    # Database migration rollback
    class RollbackManager
      def initialize(connection)
        @connection = connection
        @rollback_scripts = {}
      end

      def register_rollback(version, script)
        @rollback_scripts[version] = script
      end

      def rollback_to(version)
        current_version = get_current_version

        if version >= current_version
          puts "Cannot rollback to a version newer than current version"
          return
        end

        versions_to_rollback = @rollback_scripts.keys.select { |v| v > version }.sort.reverse

        @connection.transaction do
          versions_to_rollback.each do |v|
            execute_rollback_script(v)
            update_schema_version(v - 1)
          end
        end

        puts "Rolled back to version #{version}"
      end

      def generate_rollback_script(migration)
        # Generate automatic rollback script based on migration content
        # This is a simplified implementation
        rollback_sql = []

        # Parse the migration's up method and generate reverse operations
        # For example, if up creates a table, down drops it

        rollback_sql.join("\n")
      end

      private

      def execute_rollback_script(version)
        script = @rollback_scripts[version]
        return unless script

        if script.is_a?(String)
          @connection.execute(script)
        elsif script.is_a?(Proc)
          script.call(@connection)
        end
      end

      def update_schema_version(version)
        # Update the schema_migrations table
        @connection.execute("UPDATE schema_migrations SET version = ?", [version])
      end

      def get_current_version
        result = @connection.execute("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").first
        result ? result['version'] : 0
      end
    end
  end
end
