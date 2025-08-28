class Notification::Settings < ApplicationRecord
  belongs_to :user

  enum :bundle_email_frequency, %i[ never every_few_hours daily weekly ],
    default: :never, default: :never, prefix: :bundle_email
end
