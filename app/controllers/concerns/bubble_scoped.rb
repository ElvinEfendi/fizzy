module BubbleScoped
  extend ActiveSupport::Concern

  included do
    before_action :set_bubble
  end

  private
    def set_bubble
      @bubble = Bubble.find(params[:bubble_id])
    end
end
