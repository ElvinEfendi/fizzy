class RemoveColorFromCards < ActiveRecord::Migration[8.1]
  def change
    remove_column :cards, :color, :string
  end
end
