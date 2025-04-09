class AddColorToWorkflowStages < ActiveRecord::Migration[8.1]
  def change
    add_column :workflow_stages, :color, :string
  end
end
