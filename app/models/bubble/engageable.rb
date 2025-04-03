module Bubble::Engageable
  extend ActiveSupport::Concern

  included do
    has_one :engagement, dependent: :destroy, class_name: "Bubble::Engagement"

    scope :doing, -> { active.joins(:engagement) }
    scope :considering, -> { active.where.missing(:engagement) }
  end

  def doing?
    active? && engagement.present?
  end

  def considering?
    active? && !doing?
  end

  def engage
    unless doing?
      transaction do
        unpop
        create_engagement!
      end
    end
  end

  def reconsider
    transaction do
      unpop
      engagement&.destroy
    end
  end
end
