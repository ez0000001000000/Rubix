# Business logic and domain models
# This file contains domain models and business logic classes

module Rubix
  module Models
    # Base domain model class
    class Base < Rubix::Database::Model
      include Rubix::Core::Validations
      include Rubix::Core::Serialization
      include Rubix::Core::Callbacks

      define_callbacks :save, :create, :update, :destroy, :validation

      # Common attributes for all models
      column :id, :integer, primary_key: true, auto_increment: true
      column :created_at, :datetime, null: false
      column :updated_at, :datetime, null: false

      before_create :set_created_at
      before_save :set_updated_at

      def self.inherited(subclass)
        super
        subclass.table_name = subclass.name.tableize
      end

      def self.find_by_id(id)
        find(id) rescue nil
      end

      def self.find_or_initialize_by(attributes)
        find_by(attributes) || new(attributes)
      end

      def self.find_or_create_by(attributes)
        find_or_initialize_by(attributes).tap(&:save)
      end

      def self.create_or_update_by(attributes, updates = {})
        record = find_by(attributes)
        if record
          record.update(updates)
          record
        else
          create(attributes.merge(updates))
        end
      end

      def self.where_not(conditions)
        all.where_not(conditions)
      end

      def self.order_by(*args)
        all.order(*args)
      end

      def self.limit_by(limit)
        all.limit(limit)
      end

      def self.offset_by(offset)
        all.offset(offset)
      end

      def self.page(page, per_page = 25)
        offset_by((page - 1) * per_page).limit_by(per_page)
      end

      def self.first_or_create(attributes = {})
        first || create(attributes)
      end

      def self.first_or_initialize(attributes = {})
        first || new(attributes)
      end

      def to_param
        id.to_s
      end

      def cache_key
        "#{self.class.name.underscore}/#{id}-#{updated_at.to_i}"
      end

      def touch
        update(updated_at: Time.now)
      end

      def becomes(klass)
        became = klass.new
        became.instance_variable_set('@attributes', @attributes.dup)
        became.instance_variable_set('@new_record', @new_record)
        became.instance_variable_set('@destroyed', @destroyed)
        became
      end

      def readonly?
        false
      end

      def readonly!
        @readonly = true
        self
      end

      def frozen?
        readonly? || super
      end

      protected

      def set_created_at
        self.created_at ||= Time.now
      end

      def set_updated_at
        self.updated_at = Time.now
      end
    end

    # User model with authentication
    class User < Base
      table_name :users

      column :email, :string, null: false, unique: true
      column :encrypted_password, :string, null: false
      column :reset_password_token, :string
      column :reset_password_sent_at, :datetime
      column :remember_created_at, :datetime
      column :sign_in_count, :integer, default: 0
      column :current_sign_in_at, :datetime
      column :last_sign_in_at, :datetime
      column :current_sign_in_ip, :string
      column :last_sign_in_ip, :string
      column :confirmation_token, :string
      column :confirmed_at, :datetime
      column :confirmation_sent_at, :datetime
      column :unconfirmed_email, :string
      column :failed_attempts, :integer, default: 0
      column :unlock_token, :string
      column :locked_at, :datetime
      column :first_name, :string
      column :last_name, :string
      column :username, :string, unique: true
      column :avatar, :string
      column :bio, :text
      column :website, :string
      column :location, :string
      column :role, :string, default: 'user'
      column :active, :boolean, default: true

      validates_presence_of :email, :encrypted_password
      validates_format_of :email, with: /\A[^@\s]+@[^@\s]+\z/
      validates_uniqueness_of :email
      validates_uniqueness_of :username, allow_nil: true
      validates_length_of :username, minimum: 3, maximum: 20, allow_nil: true
      validates_length_of :encrypted_password, minimum: 60

      attr_accessor :password, :password_confirmation, :current_password

      before_save :encrypt_password
      before_create :generate_confirmation_token

      has_many :posts
      has_many :comments
      has_many :likes
      has_many :follows, foreign_key: :follower_id
      has_many :followers, class_name: 'Follow', foreign_key: :followed_id
      has_many :notifications

      def self.authenticate(email, password)
        user = find_by(email: email&.downcase&.strip)
        return nil unless user && user.active?

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

      def self.find_by_username(username)
        find_by(username: username)
      end

      def self.search(query)
        where('email LIKE ? OR username LIKE ? OR first_name LIKE ? OR last_name LIKE ?',
              "%#{query}%", "%#{query}%", "%#{query}%", "%#{query}%")
      end

      def valid_password?(password)
        return false if encrypted_password.blank?

        BCrypt::Password.new(encrypted_password).is_password?(password)
      rescue BCrypt::Errors::InvalidHash
        false
      end

      def password=(new_password)
        @password = new_password
        self.encrypted_password = encrypt_password(new_password) if new_password.present?
      end

      def full_name
        [first_name, last_name].compact.join(' ')
      end

      def display_name
        full_name.presence || username.presence || email.split('@').first
      end

      def confirmed?
        confirmed_at.present?
      end

      def confirm!
        update(confirmed_at: Time.now, confirmation_token: nil)
      end

      def generate_confirmation_token
        self.confirmation_token ||= SecureRandom.hex(20)
        self.confirmation_sent_at = Time.now
      end

      def send_confirmation_instructions
        # Send email confirmation
        update(confirmation_sent_at: Time.now)
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
        update(locked_at: Time.now, unlock_token: SecureRandom.hex(20))
      end

      def unlock_access!
        update(locked_at: nil, unlock_token: nil, failed_attempts: 0)
      end

      def access_locked?
        locked_at.present? && !lock_expired?
      end

      def lock_expired?
        locked_at && locked_at < 2.hours.ago
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

      def active_for_authentication?
        active? && confirmed?
      end

      def inactive_message
        if !active?
          :inactive
        elsif !confirmed?
          :unconfirmed
        else
          super
        end
      end

      def avatar_url(size = :medium)
        return avatar if avatar&.start_with?('http')

        if avatar.present?
          "/uploads/avatars/#{id}/#{size}_#{avatar}"
        else
          "/assets/default-avatar-#{size}.png"
        end
      end

      def following?(user)
        follows.exists?(followed_id: user.id)
      end

      def follow(user)
        follows.create(followed: user) unless following?(user)
      end

      def unfollow(user)
        follows.where(followed_id: user.id).destroy_all
      end

      def followers_count
        followers.count
      end

      def following_count
        follows.count
      end

      def posts_count
        posts.count
      end

      def liked_posts
        Post.joins(:likes).where(likes: { user_id: id })
      end

      def timeline
        Post.where(user_id: following_ids + [id]).order(created_at: :desc)
      end

      def following_ids
        follows.pluck(:followed_id)
      end

      def mention_regex
        /@#{Regexp.escape(username)}/i
      end

      private

      def encrypt_password(password = nil)
        password ||= @password
        return unless password.present?

        cost = Rubix::Application.instance.config.security_config[:bcrypt_cost] || BCrypt::Engine::DEFAULT_COST
        BCrypt::Password.create(password, cost: cost)
      end
    end

    # Post model
    class Post < Base
      table_name :posts

      column :user_id, :integer, null: false
      column :title, :string
      column :content, :text, null: false
      column :published, :boolean, default: false
      column :published_at, :datetime
      column :slug, :string, unique: true
      column :excerpt, :text
      column :featured_image, :string
      column :tags, :string
      column :category_id, :integer
      column :views_count, :integer, default: 0
      column :likes_count, :integer, default: 0
      column :comments_count, :integer, default: 0

      validates_presence_of :user_id, :content
      validates_length_of :title, maximum: 200
      validates_length_of :content, minimum: 10

      belongs_to :user
      belongs_to :category
      has_many :comments
      has_many :likes
      has_many :taggings
      has_many :tags, through: :taggings

      before_save :generate_slug, :set_published_at
      after_save :update_counters

      scope :published, -> { where(published: true) }
      scope :draft, -> { where(published: false) }
      scope :recent, -> { order(created_at: :desc) }
      scope :popular, -> { order(likes_count: :desc, views_count: :desc) }

      def self.search(query)
        where('title LIKE ? OR content LIKE ? OR excerpt LIKE ?',
              "%#{query}%", "%#{query}%", "%#{query}%")
      end

      def self.by_tag(tag_name)
        joins(:tags).where(tags: { name: tag_name })
      end

      def self.by_category(category_slug)
        joins(:category).where(categories: { slug: category_slug })
      end

      def publish!
        update(published: true, published_at: Time.now)
      end

      def unpublish!
        update(published: false, published_at: nil)
      end

      def published?
        published && published_at.present?
      end

      def draft?
        !published?
      end

      def increment_views!
        increment!(:views_count)
      end

      def liked_by?(user)
        likes.exists?(user_id: user.id)
      end

      def like(user)
        likes.create(user: user) unless liked_by?(user)
      end

      def unlike(user)
        likes.where(user_id: user.id).destroy_all
      end

      def to_param
        slug.presence || id.to_s
      end

      def excerpt(length = 160)
        return self[:excerpt] if self[:excerpt].present?

        content.gsub(/<[^>]*>/, '').strip[0..length].gsub(/\s+\z/, '') + '...'
      end

      def tag_list
        tags.map(&:name).join(', ')
      end

      def tag_list=(list)
        self.tags = list.split(',').map(&:strip).map do |tag_name|
          Tag.find_or_create_by(name: tag_name)
        end
      end

      def mentioned_users
        content.scan(/@(\w+)/).flatten.map do |username|
          User.find_by_username(username)
        end.compact
      end

      private

      def generate_slug
        return if slug.present? || title.blank?

        base_slug = title.parameterize
        counter = 1
        candidate = base_slug

        while self.class.where(slug: candidate).where.not(id: id).exists?
          candidate = "#{base_slug}-#{counter}"
          counter += 1
        end

        self.slug = candidate
      end

      def set_published_at
        self.published_at = Time.now if published? && published_at.nil?
      end

      def update_counters
        update_columns(
          likes_count: likes.count,
          comments_count: comments.count
        )
      end
    end

    # Comment model
    class Comment < Base
      table_name :comments

      column :user_id, :integer, null: false
      column :post_id, :integer, null: false
      column :parent_id, :integer
      column :content, :text, null: false
      column :approved, :boolean, default: true

      validates_presence_of :user_id, :post_id, :content
      validates_length_of :content, minimum: 2, maximum: 1000

      belongs_to :user
      belongs_to :post
      belongs_to :parent, class_name: 'Comment'
      has_many :replies, class_name: 'Comment', foreign_key: :parent_id

      scope :approved, -> { where(approved: true) }
      scope :pending, -> { where(approved: false) }
      scope :root, -> { where(parent_id: nil) }

      def approve!
        update(approved: true)
      end

      def reject!
        update(approved: false)
      end

      def root?
        parent_id.nil?
      end

      def reply?
        parent_id.present?
      end

      def depth
        return 0 if root?
        1 + parent.depth
      end

      def mentioned_users
        content.scan(/@(\w+)/).flatten.map do |username|
          User.find_by_username(username)
        end.compact
      end
    end

    # Like model
    class Like < Base
      table_name :likes

      column :user_id, :integer, null: false
      column :post_id, :integer, null: false

      validates_presence_of :user_id, :post_id
      validates_uniqueness_of :user_id, scope: :post_id

      belongs_to :user
      belongs_to :post

      def self.toggle(user, post)
        if exists?(user_id: user.id, post_id: post.id)
          where(user_id: user.id, post_id: post.id).destroy_all
          false
        else
          create(user_id: user.id, post_id: post.id)
          true
        end
      end
    end

    # Category model
    class Category < Base
      table_name :categories

      column :name, :string, null: false
      column :slug, :string, null: false, unique: true
      column :description, :text
      column :parent_id, :integer
      column :position, :integer, default: 0

      validates_presence_of :name, :slug
      validates_uniqueness_of :slug

      belongs_to :parent, class_name: 'Category'
      has_many :children, class_name: 'Category', foreign_key: :parent_id
      has_many :posts

      scope :root, -> { where(parent_id: nil) }
      scope :ordered, -> { order(position: :asc, name: :asc) }

      before_save :generate_slug

      def self.find_by_slug(slug)
        find_by(slug: slug)
      end

      def root?
        parent_id.nil?
      end

      def child?
        parent_id.present?
      end

      def descendants
        children.flat_map { |child| [child] + child.descendants }
      end

      def ancestors
        return [] if root?
        [parent] + parent.ancestors
      end

      def self_and_descendants
        [self] + descendants
      end

      def to_param
        slug
      end

      private

      def generate_slug
        return if slug.present? || name.blank?

        base_slug = name.parameterize
        counter = 1
        candidate = base_slug

        while self.class.where(slug: candidate).where.not(id: id).exists?
          candidate = "#{base_slug}-#{counter}"
          counter += 1
        end

        self.slug = candidate
      end
    end

    # Tag model
    class Tag < Base
      table_name :tags

      column :name, :string, null: false, unique: true
      column :slug, :string, null: false, unique: true
      column :color, :string

      validates_presence_of :name, :slug
      validates_uniqueness_of :name, :slug

      has_many :taggings
      has_many :posts, through: :taggings

      scope :popular, -> { order('COUNT(taggings.post_id) DESC').joins(:taggings).group(:id) }

      before_save :generate_slug

      def self.find_by_name(name)
        find_by(name: name)
      end

      def self.find_by_slug(slug)
        find_by(slug: slug)
      end

      def posts_count
        posts.count
      end

      def to_param
        slug
      end

      private

      def generate_slug
        return if slug.present? || name.blank?

        self.slug = name.parameterize
      end
    end

    # Tagging model (join table for posts and tags)
    class Tagging < Base
      table_name :taggings

      column :post_id, :integer, null: false
      column :tag_id, :integer, null: false

      validates_presence_of :post_id, :tag_id
      validates_uniqueness_of :tag_id, scope: :post_id

      belongs_to :post
      belongs_to :tag
    end

    # Follow model
    class Follow < Base
      table_name :follows

      column :follower_id, :integer, null: false
      column :followed_id, :integer, null: false

      validates_presence_of :follower_id, :followed_id
      validates_uniqueness_of :follower_id, scope: :followed_id

      belongs_to :follower, class_name: 'User'
      belongs_to :followed, class_name: 'User'

      validate :cannot_follow_self

      private

      def cannot_follow_self
        errors.add(:followed_id, "can't follow yourself") if follower_id == followed_id
      end
    end

    # Notification model
    class Notification < Base
      table_name :notifications

      column :user_id, :integer, null: false
      column :notifiable_type, :string, null: false
      column :notifiable_id, :integer, null: false
      column :action, :string, null: false
      column :read, :boolean, default: false
      column :read_at, :datetime

      validates_presence_of :user_id, :notifiable_type, :notifiable_id, :action

      belongs_to :user
      belongs_to :notifiable, polymorphic: true

      scope :unread, -> { where(read: false) }
      scope :read, -> { where(read: true) }
      scope :recent, -> { order(created_at: :desc) }

      def mark_as_read!
        update(read: true, read_at: Time.now)
      end

      def mark_as_unread!
        update(read: false, read_at: nil)
      end

      def read?
        read
      end

      def unread?
        !read
      end

      def self.create_for_follow(follow)
        create(
          user: follow.followed,
          notifiable: follow,
          action: 'followed'
        )
      end

      def self.create_for_like(like)
        return if like.user_id == like.post.user_id

        create(
          user: like.post.user,
          notifiable: like,
          action: 'liked_post'
        )
      end

      def self.create_for_comment(comment)
        return if comment.user_id == comment.post.user_id

        create(
          user: comment.post.user,
          notifiable: comment,
          action: 'commented_on_post'
        )
      end

      def self.create_for_reply(reply)
        return if reply.user_id == reply.parent.user_id

        create(
          user: reply.parent.user,
          notifiable: reply,
          action: 'replied_to_comment'
        )
      end
    end

    # Message model
    class Message < Base
      table_name :messages

      column :sender_id, :integer, null: false
      column :recipient_id, :integer, null: false
      column :subject, :string
      column :content, :text, null: false
      column :read, :boolean, default: false
      column :read_at, :datetime

      validates_presence_of :sender_id, :recipient_id, :content

      belongs_to :sender, class_name: 'User'
      belongs_to :recipient, class_name: 'User'

      scope :unread, -> { where(read: false) }
      scope :read, -> { where(read: true) }
      scope :sent, ->(user_id) { where(sender_id: user_id) }
      scope :received, ->(user_id) { where(recipient_id: user_id) }
      scope :conversation, ->(user1, user2) {
        where('(sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)',
              user1, user2, user2, user1).order(created_at: :asc)
      }

      def mark_as_read!
        update(read: true, read_at: Time.now)
      end

      def read?
        read
      end

      def unread?
        !read
      end

      def conversation_with(other_user)
        self.class.conversation(sender_id, other_user.id)
      end
    end

    # Activity model for tracking user actions
    class Activity < Base
      table_name :activities

      column :user_id, :integer, null: false
      column :action, :string, null: false
      column :trackable_type, :string
      column :trackable_id, :integer
      column :data, :text

      validates_presence_of :user_id, :action

      belongs_to :user
      belongs_to :trackable, polymorphic: true

      scope :recent, -> { order(created_at: :desc) }
      scope :by_action, ->(action) { where(action: action) }

      def self.log(user, action, trackable = nil, data = {})
        create(
          user: user,
          action: action,
          trackable: trackable,
          data: data.to_json
        )
      end

      def data_hash
        JSON.parse(data || '{}', symbolize_names: true)
      rescue JSON::ParserError
        {}
      end
    end

    # Setting model for user preferences
    class Setting < Base
      table_name :settings

      column :user_id, :integer, null: false
      column :key, :string, null: false
      column :value, :text
      column :value_type, :string, default: 'string'

      validates_presence_of :user_id, :key
      validates_uniqueness_of :key, scope: :user_id

      belongs_to :user

      def self.get(user, key, default = nil)
        setting = find_by(user_id: user.id, key: key.to_s)
        setting ? setting.typed_value : default
      end

      def self.set(user, key, value)
        setting = find_or_initialize_by(user_id: user.id, key: key.to_s)
        setting.typed_value = value
        setting.save
      end

      def typed_value
        case value_type
        when 'integer' then value.to_i
        when 'float' then value.to_f
        when 'boolean' then value == 'true'
        when 'json' then JSON.parse(value, symbolize_names: true)
        else value
        end
      end

      def typed_value=(val)
        self.value_type = case val
                          when Integer then 'integer'
                          when Float then 'float'
                          when TrueClass, FalseClass then 'boolean'
                          when Hash, Array then 'json'
                          else 'string'
                          end

        self.value = case val
                     when Hash, Array then val.to_json
                     else val.to_s
                     end
      end
    end
  end
end
