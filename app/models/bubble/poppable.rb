module Bubble::Poppable
  extend ActiveSupport::Concern

  AUTO_POP_AFTER = 30.days

  included do
    has_one :pop, dependent: :destroy

    scope :popped, -> { joins(:pop) }
    scope :active, -> { where.missing(:pop) }

    before_create -> { self.auto_pop_at = AUTO_POP_AFTER.from_now }
  end

  class_methods do
    def auto_pop_all_due
      active.where(auto_pop_at: ..Time.current).find_each do |bubble|
        bubble.pop!(user: bubble.bucket.account.users.system)
      end
    end
  end

  def update_auto_pop_at(last_activity)
    update!(auto_pop_at: last_activity + AUTO_POP_AFTER)
  end

  def popped?
    pop.present?
  end

  def active?
    !popped?
  end

  def popped_by
    pop&.user
  end

  def popped_at
    pop&.created_at
  end

  def pop!(user: Current.user)
    unless popped?
      create_pop!(user: user)
      track_event :popped, creator: user
    end
  end

  def unpop
    pop&.destroy
  end
end
