class CreateNotificationSettings < ActiveRecord::Migration[8.1]
  def change
    create_table :notification_settings do |t|
      t.references :user, null: false, foreign_key: true, index: true
      t.integer :bundle_email_frequency, default: 0, null: false

      t.timestamps

      t.index %i[ user_id bundle_email_frequency ]
    end
  end
end
