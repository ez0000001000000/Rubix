# Example applications and demos
# This file contains example Rubix applications demonstrating various features

# Example 1: Simple Blog Application
class BlogApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'blog.db'
      config.server_port = 3000
      config.logging_level = 'info'
    end

    # Define routes
    Rubix.get '/' do
      posts = Post.recent.limit(10)
      render json: posts.map(&:serializable_hash)
    end

    Rubix.get '/posts/:id' do |id|
      post = Post.find(id)
      render json: post.serializable_hash
    end

    Rubix.post '/posts' do
      authenticate_user!
      post = current_user.posts.create(params)
      if post.persisted?
        render json: post.serializable_hash, status: 201
      else
        render json: { errors: post.errors.full_messages }, status: 422
      end
    end

    Rubix.put '/posts/:id' do |id|
      post = Post.find(id)
      authorize! :edit, post

      if post.update(params)
        render json: post.serializable_hash
      else
        render json: { errors: post.errors.full_messages }, status: 422
      end
    end

    Rubix.delete '/posts/:id' do |id|
      post = Post.find(id)
      authorize! :delete, post
      post.destroy
      head :no_content
    end

    Rubix.run!
  end
end

# Example 2: REST API Application
class APIApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'api.db'
      config.server_port = 3001
      config.logging_level = 'debug'
    end

    # API versioning
    Rubix.namespace :api do
      Rubix.namespace :v1 do
        # Users API
        Rubix.resources :users, controller: UsersAPIController

        # Posts API
        Rubix.resources :posts, controller: PostsAPIController

        # Comments API
        Rubix.resources :comments, controller: CommentsAPIController

        # Authentication
        Rubix.post '/auth/login' do
          user = User.authenticate(params[:email], params[:password])
          if user
            token = JWT.encode({ user_id: user.id }, 'secret')
            render json: { token: token, user: user.serializable_hash }
          else
            render json: { error: 'Invalid credentials' }, status: 401
          end
        end

        Rubix.post '/auth/register' do
          user = User.new(params.slice(:email, :password, :first_name, :last_name))
          if user.save
            render json: user.serializable_hash, status: 201
          else
            render json: { errors: user.errors.full_messages }, status: 422
          end
        end
      end
    end

    Rubix.run!
  end
end

# API Controllers
class UsersAPIController < Rubix::Web::APIController
  def index
    users = User.all
    json_response users.map(&:serializable_hash)
  end

  def show
    user = User.find(params[:id])
    json_response user.serializable_hash
  end

  def create
    user = User.new(params)
    if user.save
      json_response user.serializable_hash, 201
    else
      json_response({ errors: user.errors.full_messages }, 422)
    end
  end

  def update
    user = User.find(params[:id])
    if user.update(params)
      json_response user.serializable_hash
    else
      json_response({ errors: user.errors.full_messages }, 422)
    end
  end

  def destroy
    user = User.find(params[:id])
    user.destroy
    head :no_content
  end
end

class PostsAPIController < Rubix::Web::APIController
  def index
    posts = Post.includes(:user).all
    json_response posts.map { |p| p.serializable_hash(include: :user) }
  end

  def show
    post = Post.includes(:user, :comments).find(params[:id])
    json_response post.serializable_hash(include: [:user, :comments])
  end

  def create
    post = current_user.posts.create(params)
    if post.persisted?
      json_response post.serializable_hash, 201
    else
      json_response({ errors: post.errors.full_messages }, 422)
    end
  end

  def update
    post = current_user.posts.find(params[:id])
    if post.update(params)
      json_response post.serializable_hash
    else
      json_response({ errors: post.errors.full_messages }, 422)
    end
  end

  def destroy
    post = current_user.posts.find(params[:id])
    post.destroy
    head :no_content
  end
end

class CommentsAPIController < Rubix::Web::APIController
  def index
    comments = Comment.all
    json_response comments.map(&:serializable_hash)
  end

  def show
    comment = Comment.find(params[:id])
    json_response comment.serializable_hash
  end

  def create
    comment = current_user.comments.create(params)
    if comment.persisted?
      json_response comment.serializable_hash, 201
    else
      json_response({ errors: comment.errors.full_messages }, 422)
    end
  end

  def update
    comment = current_user.comments.find(params[:id])
    if comment.update(params)
      json_response comment.serializable_hash
    else
      json_response({ errors: comment.errors.full_messages }, 422)
    end
  end

  def destroy
    comment = current_user.comments.find(params[:id])
    comment.destroy
    head :no_content
  end
end

# Example 3: Real-time Chat Application
class ChatApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'chat.db'
      config.server_port = 3002
      config.cache_store = :redis
      config.session_store = :redis
    end

    # WebSocket support (simplified)
    Rubix.get '/chat' do
      # Render chat interface
      render html: chat_html
    end

    Rubix.get '/api/messages' do
      messages = Message.includes(:sender).recent.limit(50)
      json_response messages.map { |m| m.serializable_hash(include: :sender) }
    end

    Rubix.post '/api/messages' do
      authenticate_user!
      message = current_user.sent_messages.create(params.slice(:content, :recipient_id))
      if message.persisted?
        broadcast_message(message)
        json_response message.serializable_hash(include: :sender), 201
      else
        json_response({ errors: message.errors.full_messages }, 422)
      end
    end

    Rubix.get '/api/conversations' do
      conversations = current_user.conversations
      json_response conversations.map do |conv|
        last_message = conv.last
        {
          with_user: conv.where.not(sender_id: current_user.id).first&.sender&.serializable_hash,
          last_message: last_message&.serializable_hash,
          unread_count: conv.where(recipient_id: current_user.id, read: false).count
        }
      end
    end

    # Real-time endpoints (simplified)
    Rubix.get '/api/stream' do
      # Server-sent events for real-time updates
      response.headers['Content-Type'] = 'text/event-stream'
      response.headers['Cache-Control'] = 'no-cache'

      # This would be implemented with EventMachine or similar
      stream do |out|
        # Subscribe to message events
        subscribe_to_messages do |message|
          out << "data: #{message.to_json}\n\n"
        end
      end
    end

    Rubix.run!
  end

  def self.chat_html
    <<-HTML
    <!DOCTYPE html>
    <html>
    <head>
      <title>Rubix Chat</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        #messages { height: 300px; overflow-y: scroll; border: 1px solid #ccc; padding: 10px; }
        #message-form { margin-top: 10px; }
        input[type="text"] { width: 300px; padding: 5px; }
        button { padding: 5px 10px; }
      </style>
    </head>
    <body>
      <h1>Rubix Chat</h1>
      <div id="messages"></div>
      <form id="message-form">
        <input type="text" id="message-input" placeholder="Type your message...">
        <button type="submit">Send</button>
      </form>

      <script>
        const messagesDiv = document.getElementById('messages');
        const messageForm = document.getElementById('message-form');
        const messageInput = document.getElementById('message-input');

        // Load existing messages
        fetch('/api/messages')
          .then(response => response.json())
          .then(messages => {
            messages.forEach(msg => displayMessage(msg));
          });

        // Send new messages
        messageForm.addEventListener('submit', (e) => {
          e.preventDefault();
          const content = messageInput.value.trim();
          if (content) {
            fetch('/api/messages', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ content: content })
            })
            .then(response => response.json())
            .then(message => {
              displayMessage(message);
              messageInput.value = '';
            });
          }
        });

        // Real-time updates
        const eventSource = new EventSource('/api/stream');
        eventSource.onmessage = (event) => {
          const message = JSON.parse(event.data);
          displayMessage(message);
        };

        function displayMessage(message) {
          const messageDiv = document.createElement('div');
          messageDiv.innerHTML = `<strong>${message.sender.email}:</strong> ${message.content}`;
          messagesDiv.appendChild(messageDiv);
          messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
      </script>
    </body>
    </html>
    HTML
  end

  def self.broadcast_message(message)
    # Broadcast to WebSocket connections or Server-sent events
    # Implementation would depend on the real-time framework used
  end

  def self.subscribe_to_messages(&block)
    # Subscribe to message events
    # Implementation would depend on the real-time framework used
  end
end

# Example 4: E-commerce Application
class EcommerceApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'ecommerce.db'
      config.server_port = 3003
      config.cache_enabled = true
      config.session_enabled = true
    end

    # Product routes
    Rubix.get '/products' do
      products = Product.all.page(params[:page]).per(params[:per_page] || 20)
      render json: {
        products: products.map(&:serializable_hash),
        pagination: {
          current_page: products.current_page,
          total_pages: products.total_pages,
          total_count: products.total_count
        }
      }
    end

    Rubix.get '/products/:id' do |id|
      product = Product.includes(:category, :reviews).find(id)
      render json: product.serializable_hash(include: [:category, :reviews])
    end

    Rubix.post '/products' do
      authenticate_admin!
      product = Product.new(params)
      if product.save
        render json: product.serializable_hash, status: 201
      else
        render json: { errors: product.errors.full_messages }, status: 422
      end
    end

    # Cart routes
    Rubix.get '/cart' do
      cart = current_user.cart || current_user.create_cart
      render json: cart.serializable_hash(include: :items)
    end

    Rubix.post '/cart/items' do
      cart = current_user.cart || current_user.create_cart
      item = cart.items.create(params.slice(:product_id, :quantity))
      if item.persisted?
        render json: item.serializable_hash, status: 201
      else
        render json: { errors: item.errors.full_messages }, status: 422
      end
    end

    Rubix.put '/cart/items/:id' do |id|
      item = current_user.cart.items.find(id)
      if item.update(params.slice(:quantity))
        render json: item.serializable_hash
      else
        render json: { errors: item.errors.full_messages }, status: 422
      end
    end

    Rubix.delete '/cart/items/:id' do |id|
      item = current_user.cart.items.find(id)
      item.destroy
      head :no_content
    end

    # Order routes
    Rubix.post '/orders' do
      cart = current_user.cart
      return render json: { error: 'Cart is empty' }, status: 422 if cart.items.empty?

      order = Order.create_from_cart(cart, current_user)
      if order.persisted?
        cart.destroy # Clear cart after order
        render json: order.serializable_hash(include: :items), status: 201
      else
        render json: { errors: order.errors.full_messages }, status: 422
      end
    end

    Rubix.get '/orders' do
      orders = current_user.orders.includes(:items)
      render json: orders.map { |o| o.serializable_hash(include: :items) }
    end

    Rubix.get '/orders/:id' do |id|
      order = current_user.orders.includes(:items).find(id)
      render json: order.serializable_hash(include: :items)
    end

    # Payment processing (simplified)
    Rubix.post '/payments' do
      order = Order.find(params[:order_id])
      authorize! :pay, order

      payment = Payment.process(order, params[:payment_method], params[:payment_details])
      if payment.success?
        order.update(status: 'paid')
        render json: { success: true, payment: payment.serializable_hash }
      else
        render json: { error: payment.error_message }, status: 422
      end
    end

    # Admin routes
    Rubix.namespace :admin do
      before_action :authenticate_admin!

      Rubix.get '/dashboard' do
        stats = {
          total_orders: Order.count,
          total_products: Product.count,
          total_users: User.count,
          revenue: Order.where(status: 'paid').sum(:total)
        }
        render json: stats
      end

      Rubix.resources :products
      Rubix.resources :orders
      Rubix.resources :users
    end

    Rubix.run!
  end
end

# Additional example models for e-commerce
class Product < Rubix::Models::Base
  table_name :products

  column :name, :string, null: false
  column :description, :text
  column :price, :decimal, null: false
  column :sku, :string, unique: true
  column :stock_quantity, :integer, default: 0
  column :category_id, :integer
  column :active, :boolean, default: true

  belongs_to :category
  has_many :order_items
  has_many :reviews

  validates_presence_of :name, :price
  validates_numericality_of :price, greater_than: 0
  validates_uniqueness_of :sku, allow_nil: true

  scope :active, -> { where(active: true) }
  scope :in_stock, -> { where('stock_quantity > 0') }
  scope :by_category, ->(category_id) { where(category_id: category_id) }

  def in_stock?
    stock_quantity > 0
  end

  def out_of_stock?
    !in_stock?
  end

  def average_rating
    reviews.average(:rating) || 0
  end
end

class Cart < Rubix::Models::Base
  table_name :carts

  column :user_id, :integer, null: false
  column :total, :decimal, default: 0

  belongs_to :user
  has_many :items, class_name: 'CartItem'

  def add_product(product, quantity = 1)
    item = items.find_by(product_id: product.id)
    if item
      item.update(quantity: item.quantity + quantity)
    else
      items.create(product: product, quantity: quantity)
    end
    update_total
  end

  def remove_product(product)
    items.where(product_id: product.id).destroy_all
    update_total
  end

  def update_quantity(product, quantity)
    item = items.find_by(product_id: product.id)
    if item && quantity > 0
      item.update(quantity: quantity)
    elsif item && quantity <= 0
      item.destroy
    end
    update_total
  end

  def clear
    items.destroy_all
    update(total: 0)
  end

  private

  def update_total
    total = items.sum('quantity * price')
    update(total: total)
  end
end

class CartItem < Rubix::Models::Base
  table_name :cart_items

  column :cart_id, :integer, null: false
  column :product_id, :integer, null: false
  column :quantity, :integer, default: 1
  column :price, :decimal, null: false

  belongs_to :cart
  belongs_to :product

  validates_presence_of :quantity, :price
  validates_numericality_of :quantity, greater_than: 0

  before_create :set_price

  private

  def set_price
    self.price = product.price
  end
end

class Order < Rubix::Models::Base
  table_name :orders

  column :user_id, :integer, null: false
  column :total, :decimal, null: false
  column :status, :string, default: 'pending'
  column :shipping_address, :text
  column :billing_address, :text

  belongs_to :user
  has_many :items, class_name: 'OrderItem'

  validates_presence_of :user_id, :total

  def self.create_from_cart(cart, user)
    order = create(
      user: user,
      total: cart.total,
      shipping_address: user.shipping_address,
      billing_address: user.billing_address
    )

    if order.persisted?
      cart.items.each do |cart_item|
        order.items.create(
          product: cart_item.product,
          quantity: cart_item.quantity,
          price: cart_item.price
        )
      end
    end

    order
  end

  def paid?
    status == 'paid'
  end

  def shipped?
    status == 'shipped'
  end

  def completed?
    status == 'completed'
  end
end

class OrderItem < Rubix::Models::Base
  table_name :order_items

  column :order_id, :integer, null: false
  column :product_id, :integer, null: false
  column :quantity, :integer, default: 1
  column :price, :decimal, null: false

  belongs_to :order
  belongs_to :product

  validates_presence_of :quantity, :price
  validates_numericality_of :quantity, greater_than: 0
end

class Payment < Rubix::Models::Base
  table_name :payments

  column :order_id, :integer, null: false
  column :amount, :decimal, null: false
  column :payment_method, :string, null: false
  column :transaction_id, :string
  column :status, :string, default: 'pending'

  belongs_to :order

  def self.process(order, payment_method, payment_details)
    # Simplified payment processing
    # In real app, integrate with payment gateway
    payment = create(
      order: order,
      amount: order.total,
      payment_method: payment_method,
      status: 'completed',
      transaction_id: SecureRandom.hex(16)
    )

    payment
  end

  def success?
    status == 'completed'
  end

  def failed?
    status == 'failed'
  end

  def pending?
    status == 'pending'
  end

  def error_message
    # Return error message based on status
    'Payment processing failed'
  end
end

class Review < Rubix::Models::Base
  table_name :reviews

  column :user_id, :integer, null: false
  column :product_id, :integer, null: false
  column :rating, :integer, null: false
  column :title, :string
  column :content, :text
  column :verified_purchase, :boolean, default: false

  belongs_to :user
  belongs_to :product

  validates_presence_of :rating
  validates_inclusion_of :rating, in: 1..5
end

# Example 5: Task Management Application
class TaskManagerApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'tasks.db'
      config.server_port = 3004
      config.cache_enabled = true
    end

    # Task routes
    Rubix.get '/tasks' do
      tasks = if params[:project_id]
                Project.find(params[:project_id]).tasks
              else
                current_user.tasks
              end

      tasks = tasks.where(status: params[:status]) if params[:status]
      tasks = tasks.where(priority: params[:priority]) if params[:priority]
      tasks = tasks.order(params[:sort_by] || 'created_at DESC')

      render json: tasks.map(&:serializable_hash)
    end

    Rubix.get '/tasks/:id' do |id|
      task = current_user.tasks.find(id)
      render json: task.serializable_hash(include: [:project, :assignee, :comments])
    end

    Rubix.post '/tasks' do
      task = current_user.created_tasks.create(params.slice(:title, :description, :priority, :due_date, :project_id, :assignee_id))
      if task.persisted?
        render json: task.serializable_hash, status: 201
      else
        render json: { errors: task.errors.full_messages }, status: 422
      end
    end

    Rubix.put '/tasks/:id' do |id|
      task = current_user.tasks.find(id)
      if task.update(params)
        render json: task.serializable_hash
      else
        render json: { errors: task.errors.full_messages }, status: 422
      end
    end

    Rubix.delete '/tasks/:id' do |id|
      task = current_user.tasks.find(id)
      task.destroy
      head :no_content
    end

    # Project routes
    Rubix.get '/projects' do
      projects = current_user.projects
      render json: projects.map(&:serializable_hash)
    end

    Rubix.post '/projects' do
      project = current_user.created_projects.create(params.slice(:name, :description, :color))
      if project.persisted?
        render json: project.serializable_hash, status: 201
      else
        render json: { errors: project.errors.full_messages }, status: 422
      end
    end

    # Team routes
    Rubix.get '/teams' do
      teams = current_user.teams
      render json: teams.map(&:serializable_hash)
    end

    Rubix.post '/teams' do
      team = Team.create(params.slice(:name, :description).merge(owner: current_user))
      if team.persisted?
        team.members.create(user: current_user, role: 'owner')
        render json: team.serializable_hash, status: 201
      else
        render json: { errors: team.errors.full_messages }, status: 422
      end
    end

    Rubix.run!
  end
end

# Task management models
class Task < Rubix::Models::Base
  table_name :tasks

  column :title, :string, null: false
  column :description, :text
  column :status, :string, default: 'todo'
  column :priority, :string, default: 'medium'
  column :due_date, :datetime
  column :completed_at, :datetime
  column :creator_id, :integer, null: false
  column :assignee_id, :integer
  column :project_id, :integer

  belongs_to :creator, class_name: 'User', foreign_key: :creator_id
  belongs_to :assignee, class_name: 'User', foreign_key: :assignee_id
  belongs_to :project
  has_many :comments, as: :commentable
  has_many :time_entries

  validates_presence_of :title, :creator_id
  validates_inclusion_of :status, in: %w[todo in_progress review done]
  validates_inclusion_of :priority, in: %w[low medium high urgent]

  scope :pending, -> { where(status: %w[todo in_progress review]) }
  scope :completed, -> { where(status: 'done') }
  scope :overdue, -> { where('due_date < ? AND status != ?', Time.now, 'done') }
  scope :due_soon, -> { where('due_date BETWEEN ? AND ?', Time.now, 7.days.from_now) }

  def complete!
    update(status: 'done', completed_at: Time.now)
  end

  def completed?
    status == 'done'
  end

  def overdue?
    due_date && due_date < Time.now && !completed?
  end

  def time_spent
    time_entries.sum(:duration)
  end
end

class Project < Rubix::Models::Base
  table_name :projects

  column :name, :string, null: false
  column :description, :text
  column :color, :string, default: '#3B82F6'
  column :status, :string, default: 'active'
  column :creator_id, :integer, null: false
  column :team_id, :integer

  belongs_to :creator, class_name: 'User', foreign_key: :creator_id
  belongs_to :team
  has_many :tasks
  has_many :members, through: :team

  validates_presence_of :name, :creator_id

  def progress_percentage
    total_tasks = tasks.count
    return 0 if total_tasks.zero?

    completed_tasks = tasks.completed.count
    (completed_tasks.to_f / total_tasks * 100).round
  end

  def overdue_tasks_count
    tasks.overdue.count
  end
end

class Team < Rubix::Models::Base
  table_name :teams

  column :name, :string, null: false
  column :description, :text
  column :owner_id, :integer, null: false

  belongs_to :owner, class_name: 'User', foreign_key: :owner_id
  has_many :members, class_name: 'TeamMember'
  has_many :users, through: :members
  has_many :projects

  validates_presence_of :name, :owner_id
end

class TeamMember < Rubix::Models::Base
  table_name :team_members

  column :team_id, :integer, null: false
  column :user_id, :integer, null: false
  column :role, :string, default: 'member'

  belongs_to :team
  belongs_to :user

  validates_presence_of :team_id, :user_id
  validates_inclusion_of :role, in: %w[owner admin member]
end

class TimeEntry < Rubix::Models::Base
  table_name :time_entries

  column :user_id, :integer, null: false
  column :task_id, :integer, null: false
  column :duration, :integer, null: false # in minutes
  column :description, :text
  column :started_at, :datetime, null: false
  column :ended_at, :datetime

  belongs_to :user
  belongs_to :task

  validates_presence_of :user_id, :task_id, :duration, :started_at
  validates_numericality_of :duration, greater_than: 0
end

# Example 6: Social Media Application
class SocialMediaApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'social.db'
      config.server_port = 3005
      config.cache_enabled = true
      config.session_enabled = true
    end

    # Post routes
    Rubix.get '/feed' do
      posts = current_user.feed.includes(:user, :likes).recent.limit(20)
      render json: posts.map { |p| p.serializable_hash(include: [:user, :likes]) }
    end

    Rubix.post '/posts' do
      post = current_user.posts.create(params.slice(:content, :image_url))
      if post.persisted?
        render json: post.serializable_hash, status: 201
      else
        render json: { errors: post.errors.full_messages }, status: 422
      end
    end

    Rubix.post '/posts/:id/like' do |id|
      post = Post.find(id)
      like = Like.toggle(current_user, post)
      render json: { liked: like }
    end

    Rubix.post '/posts/:id/comments' do |id|
      post = Post.find(id)
      comment = post.comments.create(params.slice(:content).merge(user: current_user))
      if comment.persisted?
        render json: comment.serializable_hash, status: 201
      else
        render json: { errors: comment.errors.full_messages }, status: 422
      end
    end

    # User routes
    Rubix.get '/users/:id' do |id|
      user = User.find(id)
      render json: user.serializable_hash(include: [:posts, :followers, :following])
    end

    Rubix.post '/users/:id/follow' do |id|
      user_to_follow = User.find(id)
      follow = current_user.follow(user_to_follow)
      render json: { following: true }
    end

    Rubix.delete '/users/:id/follow' do |id|
      user_to_unfollow = User.find(id)
      current_user.unfollow(user_to_unfollow)
      render json: { following: false }
    end

    # Search routes
    Rubix.get '/search' do
      query = params[:q]
      return render json: { error: 'Query required' }, status: 400 unless query

      users = User.search(query).limit(10)
      posts = Post.search(query).limit(10)

      render json: {
        users: users.map(&:serializable_hash),
        posts: posts.map(&:serializable_hash)
      }
    end

    # Notification routes
    Rubix.get '/notifications' do
      notifications = current_user.notifications.unread.recent.limit(20)
      render json: notifications.map(&:serializable_hash)
    end

    Rubix.put '/notifications/:id/read' do |id|
      notification = current_user.notifications.find(id)
      notification.mark_as_read!
      render json: notification.serializable_hash
    end

    Rubix.run!
  end
end

# Example 7: File Upload Application
class FileUploadApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'uploads.db'
      config.server_port = 3006
    end

    Rubix.post '/upload' do
      uploaded_file = params[:file]
      return render json: { error: 'No file uploaded' }, status: 400 unless uploaded_file

      file_record = UploadedFile.create(
        filename: uploaded_file[:filename],
        content_type: uploaded_file[:type],
        size: uploaded_file[:tempfile].size,
        user: current_user
      )

      if file_record.persisted?
        # Save file to disk
        file_path = File.join('uploads', "#{file_record.id}_#{file_record.filename}")
        FileUtils.mkdir_p('uploads')
        FileUtils.cp(uploaded_file[:tempfile].path, file_path)

        render json: file_record.serializable_hash, status: 201
      else
        render json: { errors: file_record.errors.full_messages }, status: 422
      end
    end

    Rubix.get '/files' do
      files = current_user.uploaded_files
      render json: files.map(&:serializable_hash)
    end

    Rubix.get '/files/:id/download' do |id|
      file_record = current_user.uploaded_files.find(id)
      file_path = File.join('uploads', "#{file_record.id}_#{file_record.filename}")

      if File.exist?(file_path)
        send_file file_path, filename: file_record.filename, type: file_record.content_type
      else
        render json: { error: 'File not found' }, status: 404
      end
    end

    Rubix.delete '/files/:id' do |id|
      file_record = current_user.uploaded_files.find(id)
      file_path = File.join('uploads', "#{file_record.id}_#{file_record.filename}")

      FileUtils.rm_f(file_path)
      file_record.destroy

      head :no_content
    end

    Rubix.run!
  end
end

class UploadedFile < Rubix::Models::Base
  table_name :uploaded_files

  column :user_id, :integer, null: false
  column :filename, :string, null: false
  column :content_type, :string, null: false
  column :size, :integer, null: false
  column :path, :string

  belongs_to :user

  validates_presence_of :user_id, :filename, :content_type, :size
  validates_numericality_of :size, greater_than: 0, less_than_or_equal_to: 10.megabytes

  def url
    "/files/#{id}/download"
  end

  def human_size
    units = ['B', 'KB', 'MB', 'GB']
    unit_index = 0
    size_bytes = size.to_f

    while size_bytes >= 1024 && unit_index < units.size - 1
      size_bytes /= 1024.0
      unit_index += 1
    end

    "#{size_bytes.round(2)} #{units[unit_index]}"
  end
end

# Example 8: Analytics Dashboard
class AnalyticsApplication
  def self.run
    Rubix.configure do |config|
      config.database_adapter = 'sqlite3'
      config.database_database = 'analytics.db'
      config.server_port = 3007
      config.cache_enabled = true
    end

    Rubix.get '/analytics/overview' do
      cache_key = "analytics_overview_#{Date.today}"
      overview = Rubix.cache.fetch(cache_key, expires_in: 1.hour) do
        {
          total_users: User.count,
          active_users_today: User.where('last_sign_in_at >= ?', Date.today).count,
          total_posts: Post.count,
          posts_today: Post.where('created_at >= ?', Date.today).count,
          total_orders: Order.count,
          revenue_today: Order.where('created_at >= ?', Date.today).sum(:total),
          top_products: Product.joins(:order_items).group('products.id').order('SUM(order_items.quantity) DESC').limit(5).pluck(:name)
        }
      end

      render json: overview
    end

    Rubix.get '/analytics/users' do
      user_stats = {
        total: User.count,
        new_this_month: User.where('created_at >= ?', Date.today.beginning_of_month).count,
        active_last_30_days: User.where('last_sign_in_at >= ?', 30.days.ago).count,
        user_growth: calculate_growth(User, 30.days),
        top_locations: User.where.not(location: nil).group(:location).order('COUNT(*) DESC').limit(10).pluck(:location, 'COUNT(*)')
      }

      render json: user_stats
    end

    Rubix.get '/analytics/revenue' do
      revenue_stats = {
        total_revenue: Order.sum(:total),
        revenue_this_month: Order.where('created_at >= ?', Date.today.beginning_of_month).sum(:total),
        average_order_value: Order.average(:total),
        revenue_by_month: Order.group("strftime('%Y-%m', created_at)").order("strftime('%Y-%m', created_at)").sum(:total)
      }

      render json: revenue_stats
    end

    Rubix.get '/analytics/products' do
      product_stats = {
        total_products: Product.count,
        products_in_stock: Product.in_stock.count,
        low_stock_products: Product.where('stock_quantity <= 10').count,
        top_selling_products: Product.joins(:order_items).group('products.id').order('SUM(order_items.quantity) DESC').limit(10).pluck(:name, 'SUM(order_items.quantity)'),
        products_by_category: Product.joins(:category).group('categories.name').count
      }

      render json: product_stats
    end

    Rubix.run!
  end

  def self.calculate_growth(model, period)
    current = model.where('created_at >= ?', period.ago).count
    previous = model.where('created_at >= ? AND created_at < ?', 2 * period.ago, period.ago).count

    if previous.zero?
      current > 0 ? 100.0 : 0.0
    else
      ((current - previous).to_f / previous * 100).round(2)
    end
  end
end

# Example runner script
if __FILE__ == $0
  puts "Rubix Framework Examples"
  puts "Available applications:"
  puts "1. Blog Application (port 3000)"
  puts "2. REST API Application (port 3001)"
  puts "3. Chat Application (port 3002)"
  puts "4. E-commerce Application (port 3003)"
  puts "5. Task Manager Application (port 3004)"
  puts "6. Social Media Application (port 3005)"
  puts "7. File Upload Application (port 3006)"
  puts "8. Analytics Dashboard (port 3007)"
  puts ""
  puts "Run individual applications by uncommenting the desired run! call"
  puts "Example: BlogApplication.run!"

  # Uncomment one of these to run a specific example:
  # BlogApplication.run!
  # APIApplication.run!
  # ChatApplication.run!
  # EcommerceApplication.run!
  # TaskManagerApplication.run!
  # SocialMediaApplication.run!
  # FileUploadApplication.run!
  # AnalyticsApplication.run!
end
