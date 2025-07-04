require "test_helper"

class Cards::CollectionsControllerTest < ActionDispatch::IntegrationTest
  setup do
    sign_in_as :kevin
  end

  test "update changes card collection" do
    card = cards(:logo)
    new_collection = collections(:private)

    assert_not_equal new_collection, card.collection

    assert_changes -> { card.reload.collection }, from: card.collection, to: new_collection do
      put card_collection_path(card), params: { collection_id: new_collection.id }
    end

    assert_redirected_to card
  end
end
