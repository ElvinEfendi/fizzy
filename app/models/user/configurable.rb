module User::Configurable
  extend ActiveSupport::Concern

  included do
    has_one :notification_settings, class_name: "Notification::Settings", dependent: :destroy
    has_many :push_subscriptions, class_name: "Push::Subscription", dependent: :delete_all

    after_create :create_notification_settings, unless: :system?
  end
end
