# Rubix Framework Documentation
# Comprehensive documentation for the Rubix Ruby web framework
# Rubix Framework

A comprehensive Ruby web framework with ORM, authentication, web server, and more.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Configuration](#configuration)
3. [Database](#database)
4. [Models](#models)
5. [Controllers](#controllers)
6. [Routing](#routing)
7. [Authentication](#authentication)
8. [Authorization](#authorization)
9. [Caching](#caching)
10. [Logging](#logging)
11. [Testing](#testing)
12. [Deployment](#deployment)
13. [API Reference](#api-reference)

## Getting Started

### Installation

```ruby
# Add to your Gemfile
gem 'rubix-framework'

# Or install directly
gem install rubix-framework
```

### Quick Start

```ruby
require 'rubix'

Rubix.configure do |config|
  config.database_adapter = 'sqlite3'
  config.database_database = 'myapp.db'
  config.server_port = 3000
end

# Define routes
Rubix.get '/' do
  'Hello, Rubix!'
end

Rubix.get '/users' do
  users = User.all
  render json: users.map(&:serializable_hash)
end

Rubix.run!
```

## Configuration

Rubix uses a centralized configuration system that supports multiple environments.

### Basic Configuration

```ruby
Rubix.configure do |config|
  # Database settings
  config.database_adapter = 'sqlite3'
  config.database_database = 'development.db'

  # Server settings
  config.server_port = 3000
  config.server_host = 'localhost'

  # Cache settings
  config.cache_store = :memory
  config.cache_ttl = 3600

  # Session settings
  config.session_store = :memory
  config.session_ttl = 86400

  # Security settings
  config.security_csrf_protection = true
  config.security_xss_protection = true

  # Logging settings
  config.logging_level = 'info'
  config.logging_format = :json
end
```

### Environment-specific Configuration

Create configuration files for different environments:

```yaml
# config/development.yml
database:
  adapter: sqlite3
  database: development.db
server:
  port: 3000
  reload: true
logging:
  level: debug

# config/production.yml
database:
  adapter: postgresql
  host: localhost
  database: myapp_prod
  username: myapp
  password: secret
server:
  port: 3000
  host: 0.0.0.0
logging:
  level: warn
```

Load environment configuration:

```ruby
Rubix.config.load_from_file("config/#{ENV['RUBIX_ENV'] || 'development'}.yml")
```

## Database

Rubix includes a built-in ORM with migration support.

### Database Setup

```ruby
# Configure database
Rubix.configure do |config|
  config.database_adapter = 'sqlite3'
  config.database_database = 'myapp.db'
end

# Initialize database
Rubix.database
```

### Migrations

```ruby
# Create a migration file
# db/migrate/001_create_users.rb
class CreateUsers < Rubix::Database::Migration
  def up
    create_table :users do |t|
      t.string :email, null: false, unique: true
      t.string :password_digest, null: false
      t.timestamps
    end
  end

  def down
    drop_table :users
  end
end

# Run migrations
Rubix::Database::Migrator.migrate
```

## Models

Models in Rubix inherit from `Rubix::Database::Model` and provide ORM functionality.

### Defining Models

```ruby
class User < Rubix::Database::Model
  # Define table name (optional, defaults to pluralized class name)
  table_name :users

  # Define columns
  column :email, :string, null: false, unique: true
  column :password_digest, :string, null: false
  column :first_name, :string
  column :last_name, :string
  column :admin, :boolean, default: false
  column :created_at, :datetime, null: false
  column :updated_at, :datetime, null: false

  # Define associations
  has_many :posts
  has_many :comments
  belongs_to :organization

  # Define validations
  validates_presence_of :email, :password_digest
  validates_format_of :email, with: /\A[^@\s]+@[^@\s]+\z/
  validates_uniqueness_of :email

  # Define callbacks
  before_save :encrypt_password
  after_create :send_welcome_email

  # Instance methods
  def full_name
    [first_name, last_name].compact.join(' ')
  end

  def admin?
    admin
  end

  private

  def encrypt_password
    if password.present?
      self.password_digest = BCrypt::Password.create(password)
    end
  end

  def send_welcome_email
    # Send welcome email
  end
end
```

### CRUD Operations

```ruby
# Create
user = User.create(email: 'user@example.com', password: 'password')
user = User.new(email: 'user@example.com')
user.password = 'password'
user.save

# Read
user = User.find(1)
users = User.all
users = User.where(email: 'user@example.com')
user = User.find_by(email: 'user@example.com')

# Update
user.update(email: 'new@example.com')
user.email = 'new@example.com'
user.save

# Delete
user.destroy
User.where(email: 'old@example.com').destroy_all
```

### Queries

```ruby
# Basic queries
users = User.where(active: true)
users = User.where('created_at > ?', 1.week.ago)
users = User.where.not(admin: true)

# Ordering
users = User.order(created_at: :desc)
users = User.order('name ASC')

# Limiting and offsetting
users = User.limit(10)
users = User.offset(20).limit(10)

# Scopes
class User < Rubix::Database::Model
  scope :active, -> { where(active: true) }
  scope :recent, -> { where('created_at > ?', 1.week.ago) }
  scope :by_name, ->(name) { where('name LIKE ?', "%#{name}%") }
end

users = User.active.recent.by_name('John')
```

### Associations

```ruby
# One-to-many
class Post < Rubix::Database::Model
  belongs_to :user
  has_many :comments
end

class Comment < Rubix::Database::Model
  belongs_to :post
  belongs_to :user
end

# Many-to-many
class User < Rubix::Database::Model
  has_many :memberships
  has_many :groups, through: :memberships
end

class Group < Rubix::Database::Model
  has_many :memberships
  has_many :users, through: :memberships
end

class Membership < Rubix::Database::Model
  belongs_to :user
  belongs_to :group
end
```

## Controllers

Controllers handle HTTP requests and return responses.

### Basic Controller

```ruby
class PostsController < Rubix::Web::Controller
  def index
    @posts = Post.all
    render json: @posts.map(&:serializable_hash)
  end

  def show
    @post = Post.find(params[:id])
    render json: @post.serializable_hash
  end

  def create
    @post = Post.new(post_params)
    if @post.save
      render json: @post.serializable_hash, status: 201
    else
      render json: { errors: @post.errors.full_messages }, status: 422
    end
  end

  def update
    @post = Post.find(params[:id])
    if @post.update(post_params)
      render json: @post.serializable_hash
    else
      render json: { errors: @post.errors.full_messages }, status: 422
    end
  end

  def destroy
    @post = Post.find(params[:id])
    @post.destroy
    head :no_content
  end

  private

  def post_params
    params.slice(:title, :content, :published)
  end
end
```

### REST Controller

```ruby
class API::PostsController < Rubix::Web::RESTController
  # Inherits index, show, create, update, destroy methods
  # Automatically handles JSON responses and parameter validation
end
```

### API Controller

```ruby
class API::V1::UsersController < Rubix::Web::APIController
  before_action :authenticate_request
  before_action :set_user, only: [:show, :update, :destroy]

  def index
    users = User.all
    json_response users.map(&:serializable_hash)
  end

  def show
    json_response @user.serializable_hash
  end

  def create
    user = User.new(user_params)
    if user.save
      json_response user.serializable_hash, 201
    else
      json_response({ errors: user.errors.full_messages }, 422)
    end
  end

  private

  def set_user
    @user = User.find(params[:id])
  end

  def user_params
    params.slice(:email, :password, :first_name, :last_name)
  end
end
```

## Routing

Rubix provides a flexible routing system.

### Basic Routes

```ruby
# HTTP methods
Rubix.get '/posts', to: 'posts#index'
Rubix.post '/posts', to: 'posts#create'
Rubix.put '/posts/:id', to: 'posts#update'
Rubix.patch '/posts/:id', to: 'posts#update'
Rubix.delete '/posts/:id', to: 'posts#destroy'

# Block syntax
Rubix.get '/health' do
  { status: 'ok', timestamp: Time.now }
end
```

### Route Parameters

```ruby
Rubix.get '/posts/:id' do |id|
  post = Post.find(id)
  render json: post.serializable_hash
end

Rubix.get '/users/:user_id/posts/:id' do |user_id, id|
  user = User.find(user_id)
  post = user.posts.find(id)
  render json: post.serializable_hash
end
```

### Namespaces

```ruby
Rubix.namespace :api do
  Rubix.get '/status' do
    { status: 'API OK' }
  end

  Rubix.namespace :v1 do
    Rubix.resources :users
    Rubix.resources :posts
  end
end
```

### Resources

```ruby
# Standard REST routes
Rubix.resources :posts

# Equivalent to:
# GET /posts, POST /posts, GET /posts/:id, PUT /posts/:id, PATCH /posts/:id, DELETE /posts/:id

# Nested resources
Rubix.resources :users do
  Rubix.resources :posts
end

# Custom routes
Rubix.resources :posts do
  Rubix.get :published, on: :collection
  Rubix.post :publish, on: :member
end
```

### Route Helpers

```ruby
# Named routes
Rubix.get '/posts/:id', to: 'posts#show', as: :post

# In controllers/views
post_path(post) # => "/posts/123"
```

## Authentication

Rubix includes built-in authentication support.

### User Model

```ruby
class User < Rubix::Models::User
  # Inherits authentication methods
end
```

### Authentication Routes

```ruby
Rubix.post '/auth/login' do
  user = User.authenticate(params[:email], params[:password])
  if user
    session[:user_id] = user.id
    redirect '/dashboard'
  else
    flash[:error] = 'Invalid credentials'
    redirect '/login'
  end
end

Rubix.post '/auth/logout' do
  session.clear
  redirect '/'
end

Rubix.post '/auth/register' do
  user = User.new(user_params)
  if user.save
    session[:user_id] = user.id
    redirect '/dashboard'
  else
    flash[:errors] = user.errors.full_messages
    redirect '/register'
  end
end
```

### Controller Authentication

```ruby
class ApplicationController < Rubix::Web::Controller
  before_action :authenticate_user!

  private

  def authenticate_user!
    unless current_user
      redirect '/login'
    end
  end
end

class PostsController < ApplicationController
  def create
    @post = current_user.posts.new(post_params)
    # ...
  end
end
```

### JWT Authentication

```ruby
# Login endpoint
Rubix.post '/api/auth/login' do
  user = User.authenticate(params[:email], params[:password])
  if user
    token = Rubix::Auth::JWT.encode({ user_id: user.id })
    json_response({ token: token, user: user.serializable_hash })
  else
    json_response({ error: 'Invalid credentials' }, 401)
  end
end

# Protected endpoint
Rubix.get '/api/profile' do
  authenticate_user!
  json_response current_user.serializable_hash
end
```

## Authorization

Rubix provides role-based authorization.

### Permission Definition

```ruby
Rubix::Auth::Permissions.define do
  permission :read_posts, 'Can read posts'
  permission :write_posts, 'Can create and edit posts'
  permission :delete_posts, 'Can delete posts'
  permission :manage_users, 'Can manage users'

  role :admin do
    can :read_posts, :write_posts, :delete_posts, :manage_users
  end

  role :editor do
    can :read_posts, :write_posts
  end

  role :user do
    can :read_posts
  end
end
```

### Controller Authorization

```ruby
class PostsController < Rubix::Web::Controller
  before_action :authorize_write!, only: [:create, :update]
  before_action :authorize_delete!, only: [:destroy]

  def create
    # Only users with write_posts permission
  end

  def destroy
    # Only users with delete_posts permission
  end

  private

  def authorize_write!
    authorize! :write_posts
  end

  def authorize_delete!
    authorize! :delete_posts
  end
end
```

## Caching

Rubix supports multiple caching strategies.

### Configuration

```ruby
Rubix.configure do |config|
  config.cache_store = :memory    # :memory, :redis, :file
  config.cache_ttl = 3600         # Default TTL in seconds
  config.cache_namespace = 'myapp' # Optional namespace
end
```

### Basic Caching

```ruby
# Cache a value
Rubix.cache.write('key', 'value', expires_in: 1.hour)

# Read from cache
value = Rubix.cache.read('key')

# Delete from cache
Rubix.cache.delete('key')

# Check if key exists
Rubix.cache.exist?('key')
```

### Controller Caching

```ruby
class PostsController < Rubix::Web::Controller
  def index
    @posts = Rubix.cache.fetch('posts_index', expires_in: 5.minutes) do
      Post.all.map(&:serializable_hash)
    end
    render json: @posts
  end
end
```

### Fragment Caching

```ruby
class PostsController < Rubix::Web::Controller
  def show
    @post = Post.find(params[:id])
    @comments = Rubix.cache.fetch("post_#{@post.id}_comments", expires_in: 10.minutes) do
      @post.comments.map(&:serializable_hash)
    end
    render json: { post: @post.serializable_hash, comments: @comments }
  end
end
```

## Logging

Rubix includes comprehensive logging capabilities.

### Configuration

```ruby
Rubix.configure do |config|
  config.logging_level = :info        # :debug, :info, :warn, :error, :fatal
  config.logging_format = :json       # :simple, :json, :logfmt, :colored
  config.logging_file = 'log/app.log' # Optional file path
end
```

### Basic Logging

```ruby
Rubix.logger.debug 'Debug message'
Rubix.logger.info 'Info message'
Rubix.logger.warn 'Warning message'
Rubix.logger.error 'Error message'
Rubix.logger.fatal 'Fatal message'
```

### Structured Logging

```ruby
Rubix.logger.info 'User login', {
  user_id: user.id,
  ip_address: request.ip,
  user_agent: request.user_agent
}
```

### Performance Logging

```ruby
# Benchmark operations
Rubix.logger.benchmark 'Database query' do
  User.all.to_a
end

# Log metrics
Rubix.logger.count 'user_registrations'
Rubix.logger.timing 'response_time', 150.5
```

## Testing

Rubix includes a comprehensive testing framework.

### Model Tests

```ruby
class UserTest < Rubix::Testing::ModelTestCase
  def test_user_creation
    user = User.create(email: 'test@example.com', password: 'password')
    assert_save user
    assert_equal 'test@example.com', user.email
  end

  def test_user_validation
    user = User.new(email: '', password: '')
    assert_not_save user
    assert_includes user.errors[:email], "can't be blank"
  end

  def test_user_authentication
    user = create_user(email: 'test@example.com', password: 'password')
    authenticated_user = User.authenticate('test@example.com', 'password')
    assert_equal user, authenticated_user
  end
end
```

### Controller Tests

```ruby
class PostsControllerTest < Rubix::Testing::ControllerTestCase
  def test_index
    create_post(title: 'Test Post')
    get :index
    assert_response 200
    assert_assigns :posts
  end

  def test_create
    post :create, { title: 'New Post', content: 'Content' }
    assert_response 201
    assert_difference 'Post.count' do
      # Already executed in post call
    end
  end
end
```

### Integration Tests

```ruby
class UserRegistrationTest < Rubix::Testing::IntegrationTestCase
  def test_user_registration
    post '/api/users', {
      email: 'new@example.com',
      password: 'password123'
    }

    assert_success
    assert_body_contains 'email'
    assert_body_contains 'new@example.com'
  end

  def test_user_login
    user = create_user(email: 'user@example.com', password: 'password')

    post '/api/auth/login', {
      email: 'user@example.com',
      password: 'password'
    }

    assert_success
    assert_body_contains 'token'
  end
end
```

### Running Tests

```ruby
# Run all tests
Rubix::Testing::TestSuite.new.run_test_directory('test')

# Run specific test
suite = Rubix::Testing::TestSuite.new
suite.add_test(UserTest)
suite.run
```

## Deployment

### Basic Deployment

1. Install Ruby and dependencies
2. Configure production environment
3. Start the application

```bash
# Install dependencies
bundle install

# Set environment
export RUBIX_ENV=production

# Start application
rubix server
```

### Configuration Files

```yaml
# config/production.yml
database:
  adapter: postgresql
  host: localhost
  database: myapp_prod
  username: myapp
  password: <%= ENV['DATABASE_PASSWORD'] %>

server:
  port: <%= ENV['PORT'] || 3000 %>
  host: 0.0.0.0

cache:
  store: redis
  url: <%= ENV['REDIS_URL'] %>

logging:
  level: info
  file: log/production.log
```

### Process Management

```ruby
# config/puma.rb
workers Integer(ENV['WEB_CONCURRENCY'] || 2)
threads_count = Integer(ENV['MAX_THREADS'] || 5)
threads threads_count, threads_count

preload_app!

rackup      DefaultRackup
port        ENV['PORT']     || 3000
environment ENV['RACK_ENV'] || 'production'

on_worker_boot do
  # Worker specific setup
  Rubix.database.reconnect!
end
```

## API Reference

### Rubix Module

#### Configuration Methods

- `Rubix.configure(&block)` - Configure the framework
- `Rubix.config` - Access configuration
- `Rubix.logger` - Access logger
- `Rubix.database` - Access database connection
- `Rubix.cache` - Access cache store

#### Application Methods

- `Rubix.get(path, &block)` - Define GET route
- `Rubix.post(path, &block)` - Define POST route
- `Rubix.put(path, &block)` - Define PUT route
- `Rubix.patch(path, &block)` - Define PATCH route
- `Rubix.delete(path, &block)` - Define DELETE route
- `Rubix.run!` - Start the application

### Database::Model

#### Class Methods

- `find(id)` - Find record by ID
- `find_by(conditions)` - Find record by conditions
- `where(conditions)` - Query records
- `all` - Get all records
- `create(attributes)` - Create new record
- `update_all(updates)` - Update all records
- `delete_all` - Delete all records
- `count` - Count records

#### Instance Methods

- `save` - Save the record
- `update(attributes)` - Update the record
- `destroy` - Delete the record
- `reload` - Reload from database
- `valid?` - Check if record is valid
- `errors` - Get validation errors

### Web::Controller

#### Instance Methods

- `render(options)` - Render response
- `redirect_to(path)` - Redirect to path
- `params` - Request parameters
- `session` - Session data
- `cookies` - Cookie data
- `request` - Request object
- `response` - Response object

### Auth::User

#### Class Methods

- `authenticate(email, password)` - Authenticate user
- `find_by_email(email)` - Find user by email

#### Instance Methods

- `valid_password?(password)` - Check password
- `reset_password!(password)` - Reset password
- `confirm!` - Confirm account
- `lock_access!` - Lock account
- `unlock_access!` - Unlock account

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

Rubix Framework is released under the MIT License.

