class Cards::CollectionsController < ApplicationController
  include CollectionScoped

  def update
    @card = Current.user.accessible_cards.find(params[:card_id])
    @card.move_to(@collection)
    redirect_to @card
  end
end
