class BoostsController < ApplicationController
  include BubbleScoped

  def index
  end

  def new
  end

  def create
    @bubble.boosts.create!
  end
end
