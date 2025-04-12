class Message < ApplicationRecord
  belongs_to :card, touch: true

  delegated_type :messageable, types: Messageable::TYPES, inverse_of: :message, dependent: :destroy

  scope :chronologically, -> { order created_at: :asc, id: :desc }

  after_create  -> { messageable.created_via(self) }
  after_destroy -> { messageable.destroyed_via(self) }
end
