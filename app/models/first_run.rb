class FirstRun
  def self.create!(user_attributes)
    account = Account.create!(name: "Fizzy")
    account.users.create!(user_attributes)
  end
end
