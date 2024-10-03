class BubblesController < ApplicationController
  include BucketScoped

  before_action :set_bubble, only: %i[ show edit update ]

  def index
    @bubbles = @bucket.bubbles.not_popped.reverse_chronologically

    if params[:filter].present?
      @bubbles = @bubbles.mentioning(params[:filter])
    end

    @most_active_bubbles = @bubbles.ordered_by_activity.limit(10)

    if params[:tag_id]
      @tag = Current.account.tags.find(params[:tag_id])
      @bubbles = @bubbles.tagged_with(@tag)
      @most_active_bubbles = @most_active_bubbles.tagged_with(@tag)
    end
  end

  def new
    @bubble = @bucket.bubbles.build
  end

  def create
    @bubble = @bucket.bubbles.create!(bubble_params)
    redirect_to bucket_bubble_url(@bucket, @bubble)
  end

  def show
  end

  def edit
  end

  def update
    @bubble.update!(bubble_params)
    redirect_to bucket_bubble_url(@bucket, @bubble)
  end

  private
    def set_bubble
      @bubble = @bucket.bubbles.find(params[:id])
    end

    def bubble_params
      params.fetch(:bubble, {}).permit(:title, :color, :due_on, :image, tag_ids: [])
    end
end
