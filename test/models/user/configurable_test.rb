require "test_helper"

class Notification::ConfigurableTest < ActiveSupport::TestCase
  test "should create a notification settings for new users" do
    user = User.create! name: "Some new user", email_address: "some.new@user.com"
    assert user.notification_settings.present?
  end
end
