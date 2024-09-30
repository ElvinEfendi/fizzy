require "test_helper"

class FirstRunsControllerTest < ActionDispatch::IntegrationTest
  setup do
    Account.destroy_all
  end

  test "show" do
    get first_run_url
    assert_response :ok
    assert_select "title", text: "Set up Fizzy"
  end

  test "show after completion" do
    Account.create! name: "Fizzy"
    get first_run_url
    assert_redirected_to root_url
  end

  test "create" do
    assert_difference -> { Account.count }, +1 do
      post first_run_url, params: { user: { name: "New", email_address: "new@37signals.com", password: "secret123456" } }
      assert_redirected_to root_url
    end

    follow_redirect!
    assert_response :ok
  end
end
