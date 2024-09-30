class FirstRunsController < ApplicationController
  allow_unauthenticated_access

  before_action :prevent_repeats

  def show
  end

  def create
    user = FirstRun.create!(user_params)
    start_new_session_for user
    redirect_to root_url
  end

  private
    def prevent_repeats
      redirect_to root_url unless Account.none?
    end

    def user_params
      params.require(:user).permit(:name, :email_address, :password)
    end
end
