class Event < ApplicationRecord
  include Particulars

  belongs_to :creator, class_name: "User"
  belongs_to :summary, touch: true, class_name: "EventSummary"

  has_one :account, through: :creator

  scope :chronologically, -> { order created_at: :asc, id: :desc }
  scope :non_boosts, -> { where.not action: :boosted }
  scope :boosts, -> { where action: :boosted }

  def generate_notifications
    Notifier.for(self)&.generate
  end

  def generate_notifications_later
    GenerateNotificationsJob.perform_later self
  end
end
