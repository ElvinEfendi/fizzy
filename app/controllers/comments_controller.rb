class CommentsController < ApplicationController
  include BubbleScoped

  def create
    @bubble.comments.create!(comment_params)
    redirect_to @bubble
  end

  private
    def comment_params
      params.require(:comment).permit(:body)
    end
end
