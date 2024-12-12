class AddUniqueIndexToProjectsIdentifier < ActiveRecord::Migration[7.2]
  def up
    add_index :projects, :identifier, :unique => true
  end

  def down
    remove_index :projects, :identifier
  end
end
