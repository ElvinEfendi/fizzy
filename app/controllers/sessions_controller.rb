class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_session_url, alert: "Try again later." }

  before_action :require_first_run_completion

  def new
  end

  def create
    if user = User.active.authenticate_by(params.permit(:email_address, :password))
      start_new_session_for user
      redirect_to after_authentication_url
    else
      redirect_to new_session_url, alert: "Try another email address or password."
    end
  end

  def destroy
    terminate_session
    redirect_to new_session_url
  end

  private
    def require_first_run_completion
      redirect_to first_run_url if Account.none?
    end
end
