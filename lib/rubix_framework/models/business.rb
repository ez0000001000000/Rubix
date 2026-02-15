# Extended business logic and domain models
# This file contains additional domain models for enterprise applications

require 'rubygems'
require 'time'
require 'date'
require 'bigdecimal'
require 'securerandom'

module Rubix
  module Models
    # Enterprise domain models
    class Organization < Base
      column :name, :string, null: false
      column :description, :text
      column :website, :string
      column :email, :string
      column :phone, :string
      column :address, :text
      column :city, :string
      column :state, :string
      column :postal_code, :string
      column :country, :string
      column :tax_id, :string
      column :industry, :string
      column :size, :string
      column :founded_at, :date
      column :status, :string, default: 'active'
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :name, presence: true, length: { minimum: 2, maximum: 100 }
      validates :email, format: { with: /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i }, allow_blank: true
      validates :website, format: { with: /\Ahttps?:\/\/[^\s<>"{}|\\^`\[\]]+\z/ }, allow_blank: true
      validates :status, inclusion: { in: ['active', 'inactive', 'suspended', 'pending'] }

      belongs_to :owner, class_name: 'User', foreign_key: :owner_id
      has_many :memberships, class_name: 'OrganizationMembership'
      has_many :users, through: :memberships
      has_many :teams, class_name: 'Team'
      has_many :projects, class_name: 'Project'
      has_many :invoices, class_name: 'Invoice'
      has_many :subscriptions, class_name: 'Subscription'

      scope :active, -> { where(status: 'active') }
      scope :inactive, -> { where(status: 'inactive') }
      scope :by_industry, ->(industry) { where(industry: industry) }
      scope :by_size, ->(size) { where(size: size) }

      before_save :normalize_website
      after_create :create_owner_membership

      def active?
        status == 'active'
      end

      def suspended?
        status == 'suspended'
      end

      def owner?(user)
        owner_id == user.id
      end

      def member?(user)
        memberships.where(user_id: user.id).exists?
      end

      def add_member(user, role = 'member')
        return if member?(user)

        memberships.create(user: user, role: role)
      end

      def remove_member(user)
        memberships.where(user_id: user.id).destroy_all
      end

      def member_count
        memberships.count
      end

      def team_count
        teams.count
      end

      def project_count
        projects.count
      end

      private

      def normalize_website
        return unless website.present?

        self.website = website.strip
        self.website = "http://#{website}" unless website.match?(/\Ahttps?:\/\//)
      end

      def create_owner_membership
        memberships.create(user: owner, role: 'owner')
      end
    end

    class OrganizationMembership < Base
      column :organization_id, :integer, null: false
      column :user_id, :integer, null: false
      column :role, :string, default: 'member'
      column :joined_at, :datetime
      column :invited_by_id, :integer
      column :invitation_sent_at, :datetime
      column :invitation_accepted_at, :datetime
      column :status, :string, default: 'active'
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :role, inclusion: { in: ['owner', 'admin', 'member', 'viewer'] }
      validates :status, inclusion: { in: ['active', 'inactive', 'pending', 'suspended'] }

      belongs_to :organization
      belongs_to :user
      belongs_to :invited_by, class_name: 'User', foreign_key: :invited_by_id

      before_create :set_joined_at
      after_create :send_invitation_email, if: :pending?

      scope :active, -> { where(status: 'active') }
      scope :pending, -> { where(status: 'pending') }
      scope :by_role, ->(role) { where(role: role) }

      def active?
        status == 'active'
      end

      def pending?
        status == 'pending'
      end

      def owner?
        role == 'owner'
      end

      def admin?
        role == 'admin'
      end

      def can_manage_organization?
        owner? || admin?
      end

      def accept_invitation
        return unless pending?

        update(
          status: 'active',
          invitation_accepted_at: Time.now
        )
      end

      def decline_invitation
        return unless pending?

        update(status: 'inactive')
      end

      private

      def set_joined_at
        self.joined_at ||= Time.now
      end

      def send_invitation_email
        # Send invitation email logic would go here
        puts "Sending invitation email to #{user.email} for organization #{organization.name}"
      end
    end

    class Team < Base
      column :organization_id, :integer, null: false
      column :name, :string, null: false
      column :description, :text
      column :color, :string
      column :avatar_url, :string
      column :is_private, :boolean, default: false
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :name, presence: true, length: { minimum: 2, maximum: 50 }
      validates :color, format: { with: /\A#[0-9A-Fa-f]{6}\z/ }, allow_blank: true

      belongs_to :organization
      has_many :team_memberships, class_name: 'TeamMembership'
      has_many :users, through: :team_memberships
      has_many :projects, class_name: 'Project'

      scope :public, -> { where(is_private: false) }
      scope :private, -> { where(is_private: true) }
      scope :by_organization, ->(org_id) { where(organization_id: org_id) }

      def public?
        !is_private
      end

      def private?
        is_private
      end

      def member?(user)
        team_memberships.where(user_id: user.id).exists?
      end

      def add_member(user, role = 'member')
        return if member?(user)

        team_memberships.create(user: user, role: role)
      end

      def remove_member(user)
        team_memberships.where(user_id: user.id).destroy_all
      end

      def member_count
        team_memberships.count
      end
    end

    class TeamMembership < Base
      column :team_id, :integer, null: false
      column :user_id, :integer, null: false
      column :role, :string, default: 'member'
      column :joined_at, :datetime
      column :added_by_id, :integer
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :role, inclusion: { in: ['owner', 'admin', 'member'] }

      belongs_to :team
      belongs_to :user
      belongs_to :added_by, class_name: 'User', foreign_key: :added_by_id

      before_create :set_joined_at

      scope :by_role, ->(role) { where(role: role) }

      def owner?
        role == 'owner'
      end

      def admin?
        role == 'admin'
      end

      def can_manage_team?
        owner? || admin?
      end

      private

      def set_joined_at
        self.joined_at ||= Time.now
      end
    end

    class Project < Base
      column :organization_id, :integer, null: false
      column :team_id, :integer
      column :name, :string, null: false
      column :description, :text
      column :status, :string, default: 'planning'
      column :priority, :string, default: 'medium'
      column :start_date, :date
      column :end_date, :date
      column :budget, :decimal, precision: 15, scale: 2
      column :progress, :integer, default: 0
      column :color, :string
      column :icon, :string
      column :is_template, :boolean, default: false
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :name, presence: true, length: { minimum: 2, maximum: 100 }
      validates :status, inclusion: { in: ['planning', 'active', 'on_hold', 'completed', 'cancelled'] }
      validates :priority, inclusion: { in: ['low', 'medium', 'high', 'urgent'] }
      validates :progress, inclusion: { in: 0..100 }
      validates :color, format: { with: /\A#[0-9A-Fa-f]{6}\z/ }, allow_blank: true

      belongs_to :organization
      belongs_to :team
      has_many :tasks, class_name: 'Task'
      has_many :milestones, class_name: 'Milestone'
      has_many :time_entries, class_name: 'TimeEntry'
      has_many :project_attachments, class_name: 'ProjectAttachment'
      has_many :project_comments, class_name: 'ProjectComment'

      scope :active, -> { where(status: 'active') }
      scope :completed, -> { where(status: 'completed') }
      scope :overdue, -> { where('end_date < ? AND status != ?', Date.today, 'completed') }
      scope :by_priority, ->(priority) { where(priority: priority) }
      scope :by_status, ->(status) { where(status: status) }
      scope :templates, -> { where(is_template: true) }

      before_save :calculate_progress

      def active?
        status == 'active'
      end

      def completed?
        status == 'completed'
      end

      def overdue?
        end_date && end_date < Date.today && !completed?
      end

      def on_track?
        return true if completed?

        progress_percentage = calculate_progress_percentage
        days_elapsed = (Date.today - start_date).to_i
        total_days = (end_date - start_date).to_i

        return false if total_days <= 0

        expected_progress = (days_elapsed.to_f / total_days * 100).round
        progress_percentage >= expected_progress - 10 # Allow 10% variance
      end

      def duration_days
        return nil unless start_date && end_date
        (end_date - start_date).to_i
      end

      def days_remaining
        return nil unless end_date && !completed?
        [0, (end_date - Date.today).to_i].max
      end

      def budget_remaining
        return nil unless budget
        budget - (time_entries.sum(:hours) * hourly_rate)
      end

      private

      def calculate_progress
        return if is_template

        total_tasks = tasks.count
        return if total_tasks.zero?

        completed_tasks = tasks.where(status: 'completed').count
        self.progress = ((completed_tasks.to_f / total_tasks) * 100).round
      end

      def calculate_progress_percentage
        total_tasks = tasks.count
        return 0 if total_tasks.zero?

        completed_tasks = tasks.where(status: 'completed').count
        (completed_tasks.to_f / total_tasks * 100).round
      end

      def hourly_rate
        # This would be configurable per project or organization
        50.0
      end
    end

    class Task < Base
      column :project_id, :integer, null: false
      column :parent_task_id, :integer
      column :assigned_to_id, :integer
      column :created_by_id, :integer, null: false
      column :title, :string, null: false
      column :description, :text
      column :status, :string, default: 'todo'
      column :priority, :string, default: 'medium'
      column :task_type, :string, default: 'task'
      column :estimated_hours, :decimal, precision: 8, scale: 2
      column :actual_hours, :decimal, precision: 8, scale: 2
      column :due_date, :date
      column :completed_at, :datetime
      column :position, :integer
      column :tags, :json
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :title, presence: true, length: { minimum: 1, maximum: 200 }
      validates :status, inclusion: { in: ['todo', 'in_progress', 'review', 'completed', 'cancelled'] }
      validates :priority, inclusion: { in: ['low', 'medium', 'high', 'urgent'] }
      validates :task_type, inclusion: { in: ['task', 'bug', 'feature', 'improvement', 'epic'] }

      belongs_to :project
      belongs_to :parent_task, class_name: 'Task', foreign_key: :parent_task_id
      belongs_to :assigned_to, class_name: 'User', foreign_key: :assigned_to_id
      belongs_to :created_by, class_name: 'User', foreign_key: :created_by_id
      has_many :subtasks, class_name: 'Task', foreign_key: :parent_task_id
      has_many :time_entries, class_name: 'TimeEntry'
      has_many :task_comments, class_name: 'TaskComment'
      has_many :task_attachments, class_name: 'TaskAttachment'

      scope :by_status, ->(status) { where(status: status) }
      scope :by_priority, ->(priority) { where(priority: priority) }
      scope :by_assignee, ->(user_id) { where(assigned_to_id: user_id) }
      scope :overdue, -> { where('due_date < ? AND status != ?', Date.today, 'completed') }
      scope :due_soon, -> { where('due_date BETWEEN ? AND ?', Date.today, Date.today + 7) }
      scope :unassigned, -> { where(assigned_to_id: nil) }

      before_save :set_completed_at

      def completed?
        status == 'completed'
      end

      def overdue?
        due_date && due_date < Date.today && !completed?
      end

      def due_soon?
        due_date && due_date.between?(Date.today, Date.today + 7) && !completed?
      end

      def mark_complete
        update(status: 'completed', completed_at: Time.now)
      end

      def assign_to(user)
        update(assigned_to: user)
      end

      def add_subtask(title, description = nil)
        subtasks.create(
          title: title,
          description: description,
          project: project,
          created_by: created_by
        )
      end

      def total_estimated_hours
        estimated_hours.to_f + subtasks.sum(:estimated_hours).to_f
      end

      def total_actual_hours
        actual_hours.to_f + subtasks.sum(:actual_hours).to_f
      end

      def progress_percentage
        return 100 if completed?

        total_subtasks = subtasks.count
        return 0 if total_subtasks.zero?

        completed_subtasks = subtasks.where(status: 'completed').count
        (completed_subtasks.to_f / total_subtasks * 100).round
      end

      private

      def set_completed_at
        if status_changed? && status == 'completed' && completed_at.nil?
          self.completed_at = Time.now
        elsif status_changed? && status != 'completed'
          self.completed_at = nil
        end
      end
    end

    class Milestone < Base
      column :project_id, :integer, null: false
      column :title, :string, null: false
      column :description, :text
      column :due_date, :date
      column :status, :string, default: 'upcoming'
      column :progress, :integer, default: 0
      column :color, :string
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :title, presence: true, length: { minimum: 2, maximum: 100 }
      validates :status, inclusion: { in: ['upcoming', 'current', 'completed', 'overdue'] }
      validates :progress, inclusion: { in: 0..100 }
      validates :color, format: { with: /\A#[0-9A-Fa-f]{6}\z/ }, allow_blank: true

      belongs_to :project
      has_many :tasks, class_name: 'Task'

      scope :upcoming, -> { where(status: 'upcoming') }
      scope :current, -> { where(status: 'current') }
      scope :completed, -> { where(status: 'completed') }
      scope :overdue, -> { where('due_date < ? AND status != ?', Date.today, 'completed') }

      before_save :update_status

      def upcoming?
        status == 'upcoming'
      end

      def current?
        status == 'current'
      end

      def completed?
        status == 'completed'
      end

      def overdue?
        due_date && due_date < Date.today && !completed?
      end

      def mark_current
        update(status: 'current')
      end

      def mark_completed
        update(status: 'completed')
      end

      private

      def update_status
        if completed?
          self.status = 'completed'
        elsif due_date && due_date < Date.today
          self.status = 'overdue'
        elsif due_date && due_date >= Date.today
          self.status = due_date <= Date.today + 7 ? 'current' : 'upcoming'
        end
      end
    end

    class TimeEntry < Base
      column :project_id, :integer, null: false
      column :task_id, :integer
      column :user_id, :integer, null: false
      column :hours, :decimal, precision: 8, scale: 2, null: false
      column :description, :text
      column :entry_date, :date, null: false
      column :billable, :boolean, default: true
      column :billed, :boolean, default: false
      column :hourly_rate, :decimal, precision: 8, scale: 2
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :hours, numericality: { greater_than: 0, less_than_or_equal_to: 24 }
      validates :entry_date, presence: true

      belongs_to :project
      belongs_to :task
      belongs_to :user

      scope :billable, -> { where(billable: true) }
      scope :billed, -> { where(billed: true) }
      scope :unbilled, -> { where(billable: true, billed: false) }
      scope :by_date_range, ->(start_date, end_date) { where(entry_date: start_date..end_date) }
      scope :by_user, ->(user_id) { where(user_id: user_id) }

      before_save :calculate_amount

      def amount
        return 0 unless billable && hourly_rate
        hours * hourly_rate
      end

      def mark_billed
        update(billed: true)
      end

      private

      def calculate_amount
        # Amount is calculated on demand, not stored
      end
    end

    class Invoice < Base
      column :organization_id, :integer, null: false
      column :client_id, :integer
      column :invoice_number, :string, null: false
      column :status, :string, default: 'draft'
      column :issue_date, :date
      column :due_date, :date
      column :subtotal, :decimal, precision: 15, scale: 2
      column :tax_amount, :decimal, precision: 15, scale: 2
      column :discount_amount, :decimal, precision: 15, scale: 2
      column :total_amount, :decimal, precision: 15, scale: 2
      column :notes, :text
      column :terms, :text
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :invoice_number, presence: true, uniqueness: true
      validates :status, inclusion: { in: ['draft', 'sent', 'paid', 'overdue', 'cancelled'] }

      belongs_to :organization
      belongs_to :client, class_name: 'User', foreign_key: :client_id
      has_many :invoice_items, class_name: 'InvoiceItem'

      scope :draft, -> { where(status: 'draft') }
      scope :sent, -> { where(status: 'sent') }
      scope :paid, -> { where(status: 'paid') }
      scope :overdue, -> { where('due_date < ? AND status NOT IN (?)', Date.today, ['paid', 'cancelled']) }

      before_save :calculate_totals

      def draft?
        status == 'draft'
      end

      def sent?
        status == 'sent'
      end

      def paid?
        status == 'paid'
      end

      def overdue?
        due_date && due_date < Date.today && !paid?
      end

      def send_invoice
        update(status: 'sent', issue_date: Date.today)
      end

      def mark_paid
        update(status: 'paid')
      end

      def add_item(description, quantity, unit_price, tax_rate = 0)
        invoice_items.create(
          description: description,
          quantity: quantity,
          unit_price: unit_price,
          tax_rate: tax_rate
        )
      end

      private

      def calculate_totals
        items_total = invoice_items.sum('quantity * unit_price')
        tax_total = invoice_items.sum('quantity * unit_price * tax_rate / 100')
        discount_total = discount_amount || 0

        self.subtotal = items_total
        self.tax_amount = tax_total
        self.total_amount = items_total + tax_total - discount_total
      end
    end

    class InvoiceItem < Base
      column :invoice_id, :integer, null: false
      column :description, :string, null: false
      column :quantity, :decimal, precision: 10, scale: 2, default: 1
      column :unit_price, :decimal, precision: 10, scale: 2, null: false
      column :tax_rate, :decimal, precision: 5, scale: 2, default: 0
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :description, presence: true
      validates :quantity, numericality: { greater_than: 0 }
      validates :unit_price, numericality: { greater_than_or_equal_to: 0 }
      validates :tax_rate, numericality: { greater_than_or_equal_to: 0, less_than_or_equal_to: 100 }

      belongs_to :invoice

      def subtotal
        quantity * unit_price
      end

      def tax_amount
        subtotal * tax_rate / 100
      end

      def total
        subtotal + tax_amount
      end
    end

    class Subscription < Base
      column :organization_id, :integer, null: false
      column :plan_name, :string, null: false
      column :status, :string, default: 'active'
      column :current_period_start, :datetime
      column :current_period_end, :datetime
      column :trial_end, :datetime
      column :cancel_at_period_end, :boolean, default: false
      column :canceled_at, :datetime
      column :amount, :decimal, precision: 10, scale: 2
      column :currency, :string, default: 'USD'
      column :interval, :string, default: 'month'
      column :interval_count, :integer, default: 1
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :plan_name, presence: true
      validates :status, inclusion: { in: ['active', 'canceled', 'past_due', 'trialing', 'incomplete'] }
      validates :currency, presence: true
      validates :interval, inclusion: { in: ['day', 'week', 'month', 'year'] }

      belongs_to :organization

      scope :active, -> { where(status: 'active') }
      scope :canceled, -> { where(status: 'canceled') }
      scope :trialing, -> { where(status: 'trialing') }

      def active?
        status == 'active'
      end

      def canceled?
        status == 'canceled'
      end

      def trialing?
        status == 'trialing'
      end

      def cancel
        update(
          status: 'canceled',
          canceled_at: Time.now,
          cancel_at_period_end: true
        )
      end

      def reactivate
        update(
          status: 'active',
          canceled_at: nil,
          cancel_at_period_end: false
        )
      end

      def on_trial?
        trialing? && trial_end && trial_end > Time.now
      end

      def days_until_trial_end
        return nil unless on_trial?
        ((trial_end - Time.now) / 86400).to_i
      end

      def days_until_period_end
        return nil unless current_period_end
        ((current_period_end - Time.now) / 86400).to_i
      end
    end

    # Communication models
    class Conversation < Base
      column :subject, :string
      column :last_message_at, :datetime
      column :message_count, :integer, default: 0
      column :participant_count, :integer, default: 0
      column :is_group, :boolean, default: false
      column :created_at, :datetime
      column :updated_at, :datetime

      has_many :messages, class_name: 'Message'
      has_many :conversation_participants, class_name: 'ConversationParticipant'

      scope :group, -> { where(is_group: true) }
      scope :direct, -> { where(is_group: false) }
      scope :recent, -> { order(last_message_at: :desc) }

      def participants
        conversation_participants.includes(:user)
      end

      def add_participant(user, role = 'member')
        conversation_participants.create(user: user, role: role)
      end

      def remove_participant(user)
        conversation_participants.where(user_id: user.id).destroy_all
      end

      def participant?(user)
        conversation_participants.where(user_id: user.id).exists?
      end

      def add_message(sender, content, message_type = 'text')
        message = messages.create(
          sender: sender,
          content: content,
          message_type: message_type
        )

        update(
          last_message_at: Time.now,
          message_count: message_count + 1
        )

        message
      end
    end

    class ConversationParticipant < Base
      column :conversation_id, :integer, null: false
      column :user_id, :integer, null: false
      column :role, :string, default: 'member'
      column :joined_at, :datetime
      column :last_read_at, :datetime
      column :is_muted, :boolean, default: false
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :role, inclusion: { in: ['owner', 'admin', 'member'] }

      belongs_to :conversation
      belongs_to :user

      before_create :set_joined_at

      def owner?
        role == 'owner'
      end

      def admin?
        role == 'admin'
      end

      def mark_as_read
        update(last_read_at: Time.now)
      end

      def unread_count
        conversation.messages.where('created_at > ?', last_read_at || joined_at).count
      end

      private

      def set_joined_at
        self.joined_at ||= Time.now
      end
    end

    class Message < Base
      column :conversation_id, :integer, null: false
      column :sender_id, :integer, null: false
      column :content, :text, null: false
      column :message_type, :string, default: 'text'
      column :metadata, :json
      column :is_edited, :boolean, default: false
      column :edited_at, :datetime
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :message_type, inclusion: { in: ['text', 'image', 'file', 'system'] }

      belongs_to :conversation
      belongs_to :sender, class_name: 'User', foreign_key: :sender_id
      has_many :message_reactions, class_name: 'MessageReaction'
      has_many :message_attachments, class_name: 'MessageAttachment'

      scope :by_type, ->(type) { where(message_type: type) }
      scope :recent, -> { order(created_at: :desc) }

      def edit(new_content)
        update(
          content: new_content,
          is_edited: true,
          edited_at: Time.now
        )
      end

      def add_reaction(user, emoji)
        message_reactions.create(user: user, emoji: emoji)
      end

      def remove_reaction(user, emoji)
        message_reactions.where(user_id: user.id, emoji: emoji).destroy_all
      end

      def reactions_summary
        message_reactions.group_by(&:emoji).transform_values do |reactions|
          {
            count: reactions.size,
            users: reactions.map(&:user)
          }
        end
      end
    end

    class MessageReaction < Base
      column :message_id, :integer, null: false
      column :user_id, :integer, null: false
      column :emoji, :string, null: false
      column :created_at, :datetime

      validates :emoji, presence: true

      belongs_to :message
      belongs_to :user
    end

    # File and attachment models
    class Attachment < Base
      column :attachable_type, :string
      column :attachable_id, :integer
      column :filename, :string, null: false
      column :content_type, :string, null: false
      column :file_size, :integer, null: false
      column :file_path, :string, null: false
      column :description, :text
      column :uploaded_by_id, :integer, null: false
      column :download_count, :integer, default: 0
      column :created_at, :datetime
      column :updated_at, :datetime

      belongs_to :uploaded_by, class_name: 'User', foreign_key: :uploaded_by_id

      # Polymorphic association
      def attachable
        return unless attachable_type && attachable_id
        attachable_type.constantize.find_by(id: attachable_id)
      end

      def url
        # Generate URL for file access
        "/attachments/#{id}/#{filename}"
      end

      def increment_download
        increment!(:download_count)
      end

      def file_extension
        File.extname(filename).downcase
      end

      def image?
        content_type.start_with?('image/')
      end

      def video?
        content_type.start_with?('video/')
      end

      def audio?
        content_type.start_with?('audio/')
      end

      def document?
        ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
         'text/plain', 'text/csv'].include?(content_type)
      end
    end

    # TaskAttachment, ProjectAttachment, MessageAttachment inherit from Attachment
    class TaskAttachment < Attachment
      belongs_to :task
    end

    class ProjectAttachment < Attachment
      belongs_to :project
    end

    class MessageAttachment < Attachment
      belongs_to :message
    end

    # Comment system
    class Comment < Base
      column :commentable_type, :string
      column :commentable_id, :integer
      column :user_id, :integer, null: false
      column :content, :text, null: false
      column :parent_comment_id, :integer
      column :is_edited, :boolean, default: false
      column :edited_at, :datetime
      column :created_at, :datetime
      column :updated_at, :datetime

      belongs_to :user
      belongs_to :parent_comment, class_name: 'Comment', foreign_key: :parent_comment_id
      has_many :replies, class_name: 'Comment', foreign_key: :parent_comment_id

      # Polymorphic association
      def commentable
        return unless commentable_type && commentable_id
        commentable_type.constantize.find_by(id: commentable_id)
      end

      def edit(new_content)
        update(
          content: new_content,
          is_edited: true,
          edited_at: Time.now
        )
      end

      def add_reply(user, content)
        replies.create(
          user: user,
          content: content,
          commentable: commentable
        )
      end

      def root_comment?
        parent_comment_id.nil?
      end

      def reply?
        !root_comment?
      end
    end

    # ProjectComment, TaskComment inherit from Comment
    class ProjectComment < Comment
      belongs_to :project
    end

    class TaskComment < Comment
      belongs_to :task
    end

    # Notification system
    class Notification < Base
      column :user_id, :integer, null: false
      column :notifiable_type, :string
      column :notifiable_id, :integer
      column :notification_type, :string, null: false
      column :title, :string, null: false
      column :message, :text
      column :data, :json
      column :read_at, :datetime
      column :action_url, :string
      column :priority, :string, default: 'normal'
      column :created_at, :datetime

      validates :notification_type, presence: true
      validates :priority, inclusion: { in: ['low', 'normal', 'high', 'urgent'] }

      belongs_to :user

      scope :unread, -> { where(read_at: nil) }
      scope :read, -> { where.not(read_at: nil) }
      scope :by_type, ->(type) { where(notification_type: type) }
      scope :by_priority, ->(priority) { where(priority: priority) }
      scope :recent, -> { order(created_at: :desc) }

      # Polymorphic association
      def notifiable
        return unless notifiable_type && notifiable_id
        notifiable_type.constantize.find_by(id: notifiable_id)
      end

      def read?
        read_at.present?
      end

      def unread?
        !read?
      end

      def mark_as_read
        update(read_at: Time.now)
      end

      def mark_as_unread
        update(read_at: nil)
      end
    end

    # Audit trail
    class AuditLog < Base
      column :auditable_type, :string
      column :auditable_id, :integer
      column :user_id, :integer
      column :action, :string, null: false
      column :old_values, :json
      column :new_values, :json
      column :changes, :json
      column :ip_address, :string
      column :user_agent, :string
      column :created_at, :datetime

      validates :action, presence: true

      belongs_to :user

      scope :by_action, ->(action) { where(action: action) }
      scope :by_user, ->(user_id) { where(user_id: user_id) }
      scope :recent, -> { order(created_at: :desc) }

      # Polymorphic association
      def auditable
        return unless auditable_type && auditable_id
        auditable_type.constantize.find_by(id: auditable_id)
      end

      def changes_summary
        return {} unless changes

        changes.transform_values do |change|
          {
            old: change['old'],
            new: change['new']
          }
        end
      end
    end

    # API key management
    class ApiKey < Base
      column :user_id, :integer, null: false
      column :organization_id, :integer
      column :name, :string, null: false
      column :key, :string, null: false
      column :permissions, :json
      column :last_used_at, :datetime
      column :expires_at, :datetime
      column :revoked_at, :datetime
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :name, presence: true
      validates :key, presence: true, uniqueness: true

      belongs_to :user
      belongs_to :organization

      scope :active, -> { where(revoked_at: nil).where('expires_at IS NULL OR expires_at > ?', Time.now) }
      scope :expired, -> { where('expires_at <= ?', Time.now) }
      scope :revoked, -> { where.not(revoked_at: nil) }

      before_create :generate_key

      def active?
        revoked_at.nil? && (expires_at.nil? || expires_at > Time.now)
      end

      def expired?
        expires_at && expires_at <= Time.now
      end

      def revoked?
        revoked_at.present?
      end

      def revoke
        update(revoked_at: Time.now)
      end

      def has_permission?(permission)
        return false unless active?
        return true if permissions.nil? # Full access if no specific permissions

        Array(permissions).include?(permission.to_s)
      end

      def record_usage
        update(last_used_at: Time.now)
      end

      private

      def generate_key
        self.key ||= "rubix_#{SecureRandom.hex(32)}"
      end
    end

    # Integration models
    class Integration < Base
      column :organization_id, :integer, null: false
      column :name, :string, null: false
      column :provider, :string, null: false
      column :config, :json
      column :status, :string, default: 'inactive'
      column :last_sync_at, :datetime
      column :error_message, :text
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :name, presence: true
      validates :provider, presence: true
      validates :status, inclusion: { in: ['active', 'inactive', 'error'] }

      belongs_to :organization

      scope :active, -> { where(status: 'active') }
      scope :by_provider, ->(provider) { where(provider: provider) }

      def active?
        status == 'active'
      end

      def activate
        update(status: 'active')
      end

      def deactivate
        update(status: 'inactive')
      end

      def mark_error(error_message)
        update(
          status: 'error',
          error_message: error_message,
          last_sync_at: Time.now
        )
      end

      def clear_error
        update(status: 'active', error_message: nil)
      end

      def sync
        # Integration-specific sync logic would go here
        update(last_sync_at: Time.now)
      end
    end

    # Workflow and automation
    class Workflow < Base
      column :organization_id, :integer, null: false
      column :name, :string, null: false
      column :description, :text
      column :trigger_type, :string
      column :trigger_config, :json
      column :actions, :json
      column :is_active, :boolean, default: true
      column :created_by_id, :integer, null: false
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :name, presence: true
      validates :trigger_type, presence: true

      belongs_to :organization
      belongs_to :created_by, class_name: 'User', foreign_key: :created_by_id

      scope :active, -> { where(is_active: true) }
      scope :by_trigger, ->(trigger_type) { where(trigger_type: trigger_type) }

      def active?
        is_active
      end

      def activate
        update(is_active: true)
      end

      def deactivate
        update(is_active: false)
      end

      def execute(context = {})
        return unless active?

        actions.each do |action|
          execute_action(action, context)
        end
      end

      private

      def execute_action(action_config, context)
        # Workflow action execution logic would go here
        # This could integrate with various services
        puts "Executing action: #{action_config['type']} with config: #{action_config['config']}"
      end
    end

    # Analytics and reporting
    class AnalyticsEvent < Base
      column :user_id, :integer
      column :organization_id, :integer
      column :event_type, :string, null: false
      column :event_name, :string, null: false
      column :properties, :json
      column :timestamp, :datetime, null: false
      column :session_id, :string
      column :ip_address, :string
      column :user_agent, :string
      column :created_at, :datetime

      validates :event_type, presence: true
      validates :event_name, presence: true

      belongs_to :user
      belongs_to :organization

      scope :by_type, ->(event_type) { where(event_type: event_type) }
      scope :by_name, ->(event_name) { where(event_name: event_name) }
      scope :by_date_range, ->(start_date, end_date) { where(timestamp: start_date..end_date) }
      scope :by_user, ->(user_id) { where(user_id: user_id) }

      before_create :set_timestamp

      private

      def set_timestamp
        self.timestamp ||= Time.now
      end
    end

    class Report < Base
      column :organization_id, :integer, null: false
      column :name, :string, null: false
      column :description, :text
      column :report_type, :string, null: false
      column :config, :json
      column :schedule, :string
      column :last_run_at, :datetime
      column :next_run_at, :datetime
      column :is_active, :boolean, default: true
      column :created_by_id, :integer, null: false
      column :created_at, :datetime
      column :updated_at, :datetime

      validates :name, presence: true
      validates :report_type, presence: true
      validates :schedule, inclusion: { in: ['manual', 'daily', 'weekly', 'monthly'] }, allow_nil: true

      belongs_to :organization
      belongs_to :created_by, class_name: 'User', foreign_key: :created_by_id

      scope :active, -> { where(is_active: true) }
      scope :by_type, ->(report_type) { where(report_type: report_type) }
      scope :scheduled, -> { where.not(schedule: nil) }

      def active?
        is_active
      end

      def scheduled?
        schedule.present? && schedule != 'manual'
      end

      def run
        # Report generation logic would go here
        update(last_run_at: Time.now)
        schedule_next_run if scheduled?
      end

      def schedule_next_run
        return unless scheduled?

        next_run = case schedule
                   when 'daily'
                     last_run_at + 1.day
                   when 'weekly'
                     last_run_at + 1.week
                   when 'monthly'
                     last_run_at + 1.month
                   end

        update(next_run_at: next_run)
      end

      def due_for_run?
        return false unless scheduled?
        next_run_at && next_run_at <= Time.now
      end
    end
  end
end
