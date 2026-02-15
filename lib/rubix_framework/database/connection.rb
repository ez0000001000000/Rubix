# Database abstraction layer with ORM-like functionality
# This file contains database connection, model classes, and query building

module Rubix
  module Database
    # Database connection manager
    class Connection
      attr_reader :config, :connection_pool

      def initialize(config = {})
        @config = config
        @connection_pool = []
        @pool_size = config.fetch(:pool_size, 5)
        @pool_mutex = Mutex.new
        @available_connections = Queue.new

        establish_connections
      end

      def execute(sql, params = [])
        connection = checkout_connection
        begin
          result = connection.execute(sql, params)
          yield result if block_given?
          result
        ensure
          checkin_connection(connection)
        end
      end

      def transaction(&block)
        connection = checkout_connection
        begin
          connection.transaction(&block)
        ensure
          checkin_connection(connection)
        end
      end

      def table_exists?(table_name)
        execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", [table_name]) do |result|
          result.any?
        end
      end

      def column_exists?(table_name, column_name)
        execute("PRAGMA table_info(#{table_name})") do |result|
          result.any? { |row| row['name'] == column_name }
        end
      end

      def create_table(table_name, &block)
        table_definition = TableDefinition.new(table_name)
        table_definition.instance_eval(&block)

        sql = table_definition.to_sql
        execute(sql)
      end

      def drop_table(table_name)
        execute("DROP TABLE IF EXISTS #{table_name}")
      end

      def add_column(table_name, column_name, type, options = {})
        sql = "ALTER TABLE #{table_name} ADD COLUMN #{column_definition(column_name, type, options)}"
        execute(sql)
      end

      def remove_column(table_name, column_name)
        # SQLite doesn't support DROP COLUMN directly
        # This is a simplified implementation
        execute("ALTER TABLE #{table_name} DROP COLUMN #{column_name}")
      rescue
        # Handle SQLite limitation
        recreate_table_without_column(table_name, column_name)
      end

      def add_index(table_name, column_names, options = {})
        index_name = options[:name] || "index_#{table_name}_on_#{Array(column_names).join('_and_')}"
        unique = options[:unique] ? 'UNIQUE ' : ''
        columns = Array(column_names).join(', ')

        sql = "CREATE #{unique}INDEX #{index_name} ON #{table_name} (#{columns})"
        execute(sql)
      end

      def remove_index(table_name, index_name)
        execute("DROP INDEX IF EXISTS #{index_name}")
      end

      private

      def establish_connections
        @pool_size.times do
          connection = create_connection
          @available_connections << connection
        end
      end

      def create_connection
        case @config[:adapter]
        when 'sqlite3', nil
          require 'sqlite3'
          SQLite3::Database.new(@config[:database] || ':memory:')
        when 'postgresql'
          require 'pg'
          PG.connect(@config)
        when 'mysql2'
          require 'mysql2'
          Mysql2::Client.new(@config)
        else
          raise ConfigurationError, "Unsupported database adapter: #{@config[:adapter]}"
        end
      end

      def checkout_connection
        @pool_mutex.synchronize do
          @available_connections.pop(true) # non-blocking
        end
      rescue ThreadError
        # Pool exhausted, create new connection
        create_connection
      end

      def checkin_connection(connection)
        @pool_mutex.synchronize do
          @available_connections << connection if @available_connections.size < @pool_size
        end
      end

      def column_definition(column_name, type, options = {})
        sql = "#{column_name} #{sql_type(type)}"

        sql << ' PRIMARY KEY' if options[:primary_key]
        sql << ' AUTOINCREMENT' if options[:auto_increment] && type == :integer
        sql << ' NOT NULL' if options[:null] == false
        sql << ' UNIQUE' if options[:unique]
        sql << " DEFAULT #{default_value(options[:default])}" if options.key?(:default)

        sql
      end

      def sql_type(type)
        case type
        when :string, :text then 'TEXT'
        when :integer then 'INTEGER'
        when :float, :decimal then 'REAL'
        when :boolean then 'BOOLEAN'
        when :date then 'DATE'
        when :datetime, :timestamp then 'DATETIME'
        when :binary then 'BLOB'
        else type.to_s.upcase
        end
      end

      def default_value(value)
        case value
        when String then "'#{value}'"
        when TrueClass then '1'
        when FalseClass then '0'
        when NilClass then 'NULL'
        else value.to_s
        end
      end

      def recreate_table_without_column(table_name, column_name)
        # Get current table schema
        columns = execute("PRAGMA table_info(#{table_name})").map do |row|
          row['name'] unless row['name'] == column_name
        end.compact

        # Get current data
        data = execute("SELECT #{columns.join(', ')} FROM #{table_name}")

        # Drop and recreate table
        execute("DROP TABLE #{table_name}")

        # Create new table definition (simplified)
        create_sql = "CREATE TABLE #{table_name} ("
        create_sql << columns.map { |col| "#{col} TEXT" }.join(', ')
        create_sql << ")"

        execute(create_sql)

        # Insert data back
        unless data.empty?
          placeholders = (['?'] * columns.size).join(', ')
          insert_sql = "INSERT INTO #{table_name} (#{columns.join(', ')}) VALUES (#{placeholders})"
          data.each do |row|
            execute(insert_sql, row.values)
          end
        end
      end

      class TableDefinition
        def initialize(table_name)
          @table_name = table_name
          @columns = []
        end

        def column(name, type, options = {})
          @columns << [name, type, options]
        end

        def string(name, options = {})
          column(name, :string, options)
        end

        def text(name, options = {})
          column(name, :text, options)
        end

        def integer(name, options = {})
          column(name, :integer, options)
        end

        def float(name, options = {})
          column(name, :float, options)
        end

        def decimal(name, options = {})
          column(name, :decimal, options)
        end

        def boolean(name, options = {})
          column(name, :boolean, options)
        end

        def date(name, options = {})
          column(name, :date, options)
        end

        def datetime(name, options = {})
          column(name, :datetime, options)
        end

        def timestamp(name, options = {})
          column(name, :timestamp, options)
        end

        def binary(name, options = {})
          column(name, :binary, options)
        end

        def timestamps
          datetime :created_at, null: false
          datetime :updated_at, null: false
        end

        def to_sql
          sql = "CREATE TABLE #{@table_name} ("
          sql << @columns.map do |name, type, options|
            column_definition(name, type, options)
          end.join(', ')
          sql << ")"
          sql
        end

        private

        def column_definition(name, type, options)
          sql = "#{name} #{sql_type(type)}"

          sql << ' PRIMARY KEY' if options[:primary_key]
          sql << ' AUTOINCREMENT' if options[:auto_increment] && type == :integer
          sql << ' NOT NULL' if options[:null] == false
          sql << ' UNIQUE' if options[:unique]
          sql << " DEFAULT #{default_value(options[:default])}" if options.key?(:default)

          sql
        end

        def sql_type(type)
          case type
          when :string, :text then 'TEXT'
          when :integer then 'INTEGER'
          when :float, :decimal then 'REAL'
          when :boolean then 'BOOLEAN'
          when :date then 'DATE'
          when :datetime, :timestamp then 'DATETIME'
          when :binary then 'BLOB'
          else type.to_s.upcase
          end
        end

        def default_value(value)
          case value
          when String then "'#{value}'"
          when TrueClass then '1'
          when FalseClass then '0'
          when NilClass then 'NULL'
          else value.to_s
          end
        end
      end
    end

    # Query builder for constructing SQL queries
    class QueryBuilder
      attr_reader :table_name, :selects, :joins, :wheres, :orders, :limit_value, :offset_value, :group_by

      def initialize(table_name)
        @table_name = table_name
        @selects = ['*']
        @joins = []
        @wheres = []
        @orders = []
        @limit_value = nil
        @offset_value = nil
        @group_by = []
      end

      def select(*columns)
        @selects = columns.flatten.map(&:to_s)
        self
      end

      def where(conditions)
        case conditions
        when Hash
          conditions.each do |column, value|
            @wheres << "#{column} = ?"
            @where_values ||= []
            @where_values << value
          end
        when String
          @wheres << conditions
        end
        self
      end

      def join(table, conditions = nil)
        join_sql = "JOIN #{table}"
        join_sql << " ON #{conditions}" if conditions
        @joins << join_sql
        self
      end

      def left_join(table, conditions = nil)
        join_sql = "LEFT JOIN #{table}"
        join_sql << " ON #{conditions}" if conditions
        @joins << join_sql
        self
      end

      def inner_join(table, conditions = nil)
        join_sql = "INNER JOIN #{table}"
        join_sql << " ON #{conditions}" if conditions
        @joins << join_sql
        self
      end

      def order(*args)
        args.each do |arg|
          case arg
          when Hash
            arg.each do |column, direction|
              @orders << "#{column} #{direction.upcase}"
            end
          when String
            @orders << arg
          end
        end
        self
      end

      def limit(value)
        @limit_value = value
        self
      end

      def offset(value)
        @offset_value = value
        self
      end

      def group(*columns)
        @group_by = columns.flatten.map(&:to_s)
        self
      end

      def to_sql
        sql = "SELECT #{select_clause}"
        sql << " FROM #{from_clause}"
        sql << " #{join_clause}" unless @joins.empty?
        sql << " #{where_clause}" unless @wheres.empty?
        sql << " #{group_clause}" unless @group_by.empty?
        sql << " #{order_clause}" unless @orders.empty?
        sql << " #{limit_clause}" if @limit_value
        sql << " #{offset_clause}" if @offset_value
        sql.strip
      end

      def where_values
        @where_values || []
      end

      private

      def select_clause
        @selects.join(', ')
      end

      def from_clause
        @table_name
      end

      def join_clause
        @joins.join(' ')
      end

      def where_clause
        "WHERE #{@wheres.join(' AND ')}"
      end

      def order_clause
        "ORDER BY #{@orders.join(', ')}"
      end

      def limit_clause
        "LIMIT #{@limit_value}"
      end

      def offset_clause
        "OFFSET #{@offset_value}"
      end

      def group_clause
        "GROUP BY #{@group_by.join(', ')}"
      end
    end

    # Base model class with ORM functionality
    class Model < Rubix::Core::Base
      include Rubix::Core::Validations
      include Rubix::Core::Serialization
      include Rubix::Core::Callbacks

      define_callbacks :save, :create, :update, :destroy, :validation

      class << self
        attr_accessor :table_name, :primary_key, :connection

        def inherited(subclass)
          subclass.table_name = subclass.name.tableize
          subclass.primary_key = :id
          subclass.connection = Rubix::Application.instance.database
        end

        def establish_connection(config)
          @connection = Connection.new(config)
        end

        def table_name=(name)
          @table_name = name
        end

        def primary_key=(key)
          @primary_key = key
        end

        def column(name, type, options = {})
          @columns ||= {}
          @columns[name] = { type: type }.merge(options)
        end

        def belongs_to(association, options = {})
          define_method(association) do
            foreign_key = options[:foreign_key] || "#{association}_id"
            associated_class = options[:class_name] || association.to_s.classify.constantize
            associated_class.find(send(foreign_key))
          end

          define_method("#{association}=") do |object|
            foreign_key = options[:foreign_key] || "#{association}_id"
            send("#{foreign_key}=", object&.id)
            instance_variable_set("@#{association}", object)
          end
        end

        def has_many(association, options = {})
          define_method(association) do
            foreign_key = options[:foreign_key] || "#{self.class.name.underscore}_id"
            associated_class = options[:class_name] || association.to_s.singularize.classify.constantize
            associated_class.where(foreign_key => id)
          end

          define_method("#{association}=") do |objects|
            # Implementation for setting has_many associations
          end
        end

        def has_one(association, options = {})
          define_method(association) do
            foreign_key = options[:foreign_key] || "#{self.class.name.underscore}_id"
            associated_class = options[:class_name] || association.to_s.classify.constantize
            associated_class.where(foreign_key => id).first
          end

          define_method("#{association}=") do |object|
            foreign_key = options[:foreign_key] || "#{self.class.name.underscore}_id"
            send("#{foreign_key}=", object&.id)
            instance_variable_set("@#{association}", object)
          end
        end

        def validates_uniqueness_of(*attributes)
          attributes.each do |attribute|
            validates attribute, uniqueness: true
          end
        end

        def scope(name, lambda = nil, &block)
          scope_lambda = lambda || block
          define_singleton_method(name) do |*args|
            relation = all
            relation.instance_exec(*args, &scope_lambda)
          end
        end

        def default_scope(lambda = nil, &block)
          @default_scope = lambda || block
        end

        def all
          Relation.new(self)
        end

        def where(conditions = {})
          all.where(conditions)
        end

        def find(id)
          where(primary_key => id).first || raise(RecordNotFound, "Couldn't find #{name} with #{primary_key}=#{id}")
        end

        def find_by(conditions = {})
          where(conditions).first
        end

        def first
          order(primary_key => :asc).limit(1).first
        end

        def last
          order(primary_key => :desc).limit(1).first
        end

        def count
          query = QueryBuilder.new(table_name).select('COUNT(*)')
          result = connection.execute(query.to_sql).first
          result.values.first.to_i
        end

        def exists?(conditions = {})
          where(conditions).limit(1).count > 0
        end

        def create(attributes = {})
          new(attributes).tap(&:save)
        end

        def create!(attributes = {})
          new(attributes).tap(&:save!)
        end

        def update_all(updates)
          # Implementation for updating all records
        end

        def delete_all
          connection.execute("DELETE FROM #{table_name}")
        end

        def transaction(&block)
          connection.transaction(&block)
        end

        def columns
          @columns ||= {}
        end

        private

        def relation
          Relation.new(self)
        end
      end

      def initialize(attributes = {})
        super(attributes)
        @errors = Rubix::Core::Validations::Errors.new(self)
      end

      def save
        run_callbacks(:validation, :before)
        return false unless valid?
        run_callbacks(:validation, :after)

        run_callbacks(:save, :before)
        result = new_record? ? create : update
        run_callbacks(:save, :after) if result
        result
      end

      def destroy
        run_callbacks(:destroy, :before)
        result = delete
        run_callbacks(:destroy, :after) if result
        result
      end

      private

      def create
        run_callbacks(:create, :before)

        attributes_to_insert = attributes.dup
        attributes_to_insert.delete(:id) if attributes_to_insert.key?(:id)

        columns = attributes_to_insert.keys.map(&:to_s)
        values = attributes_to_insert.values
        placeholders = (['?'] * columns.size).join(', ')

        sql = "INSERT INTO #{self.class.table_name} (#{columns.join(', ')}) VALUES (#{placeholders})"

        self.class.connection.execute(sql, values)
        self.id = self.class.connection.execute("SELECT last_insert_rowid()").first.values.first

        @new_record = false
        run_callbacks(:create, :after)
        true
      end

      def update
        run_callbacks(:update, :before)

        attributes_to_update = attributes.dup
        attributes_to_update.delete(:id)

        set_clause = attributes_to_update.keys.map { |k| "#{k} = ?" }.join(', ')
        values = attributes_to_update.values + [id]

        sql = "UPDATE #{self.class.table_name} SET #{set_clause} WHERE #{self.class.primary_key} = ?"

        self.class.connection.execute(sql, values)
        run_callbacks(:update, :after)
        true
      end

      def delete
        sql = "DELETE FROM #{self.class.table_name} WHERE #{self.class.primary_key} = ?"
        self.class.connection.execute(sql, [id])
        @destroyed = true
        true
      end

      def validate_uniqueness(attribute, value, options)
        return if value.nil?

        query = self.class.where(attribute => value)
        query = query.where.not(self.class.primary_key => id) unless new_record?

        if query.exists?
          @errors.add(attribute, :taken)
        end
      end
    end

    # Relation class for building queries
    class Relation
      attr_reader :klass, :query_builder

      def initialize(klass)
        @klass = klass
        @query_builder = QueryBuilder.new(klass.table_name)
        @loaded = false
        @records = []
      end

      def where(conditions = {})
        case conditions
        when Hash
          conditions.each do |key, value|
            @query_builder.where(key => value)
          end
        when String
          @query_builder.where(conditions)
        end
        self
      end

      def not(conditions)
        # Simplified NOT implementation
        self
      end

      def order(*args)
        @query_builder.order(*args)
        self
      end

      def limit(value)
        @query_builder.limit(value)
        self
      end

      def offset(value)
        @query_builder.offset(value)
        self
      end

      def group(*columns)
        @query_builder.group(*columns)
        self
      end

      def joins(*args)
        args.each do |arg|
          @query_builder.join(arg)
        end
        self
      end

      def left_joins(*args)
        args.each do |arg|
          @query_builder.left_join(arg)
        end
        self
      end

      def includes(*associations)
        # Implementation for eager loading
        self
      end

      def select(*columns)
        @query_builder.select(*columns)
        self
      end

      def distinct
        # Implementation for DISTINCT
        self
      end

      def count
        query = QueryBuilder.new(@klass.table_name).select('COUNT(*)')
        query.wheres = @query_builder.wheres.dup
        query.where_values = @query_builder.where_values.dup

        result = @klass.connection.execute(query.to_sql, query.where_values).first
        result.values.first.to_i
      end

      def first
        limit(1).to_a.first
      end

      def last
        order(@klass.primary_key => :desc).limit(1).first
      end

      def exists?
        limit(1).count > 0
      end

      def any?
        exists?
      end

      def empty?
        !exists?
      end

      def pluck(*columns)
        select(*columns).map do |record|
          columns.size == 1 ? record.send(columns.first) : columns.map { |col| record.send(col) }
        end
      end

      def to_a
        load_records unless loaded?
        @records
      end

      def each(&block)
        to_a.each(&block)
      end

      def map(&block)
        to_a.map(&block)
      end

      def find_each(&block)
        # Implementation for finding in batches
        each(&block)
      end

      def size
        count
      end

      def length
        size
      end

      private

      def loaded?
        @loaded
      end

      def load_records
        sql = @query_builder.to_sql
        results = @klass.connection.execute(sql, @query_builder.where_values)

        @records = results.map do |row|
          attributes = {}
          row.each do |column, value|
            attributes[column.to_sym] = value
          end
          @klass.new(attributes).tap { |r| r.instance_variable_set(:@new_record, false) }
        end

        @loaded = true
      end
    end

    # Migration system
    class Migration
      attr_reader :version

      def initialize(version)
        @version = version
      end

      def up
        # Implementation in subclasses
      end

      def down
        # Implementation in subclasses
      end
    end

    # Migration runner
    class Migrator
      def self.migrate(direction = :up)
        migrations_path = File.join(Dir.pwd, 'db', 'migrate')
        return unless Dir.exist?(migrations_path)

        migrations = Dir.glob(File.join(migrations_path, '*.rb')).sort.map do |file|
          version = File.basename(file, '.rb').split('_').first.to_i
          require file
          migration_class = File.basename(file, '.rb').camelize.constantize
          MigrationWrapper.new(version, migration_class.new(version))
        end

        case direction
        when :up
          migrations.each { |migration| migration.up }
        when :down
          migrations.reverse.each { |migration| migration.down }
        end
      end

      class MigrationWrapper
        attr_reader :version, :migration

        def initialize(version, migration)
          @version = version
          @migration = migration
        end

        def up
          @migration.up
        end

        def down
          @migration.down
        end
      end
    end

    # Custom exceptions
    class RecordNotFound < Rubix::Error; end
    class RecordInvalid < Rubix::Error; end
    class StatementInvalid < Rubix::Error; end
  end
end
