class Event < ApplicationRecord
  include Notifiable, Particulars

  belongs_to :collection
  belongs_to :creator, class_name: "User"
  belongs_to :eventable, polymorphic: true
  belongs_to :summary, touch: true, class_name: "EventSummary", optional: true

  scope :chronologically, -> { order created_at: :asc, id: :desc }

  after_create -> { eventable.event_was_created(self) }

  def action
    super.inquiry
  end

  def notifiable_target
    if action.commented?
      comment
    else
      eventable
    end
  end

  # TODO: This doesn't belong here anymore
  def initial_assignment?
    action == "card_published" && eventable.assigned_to?(creator)
  end
end
