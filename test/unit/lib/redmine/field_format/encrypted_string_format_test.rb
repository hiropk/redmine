# frozen_string_literal: true

# Redmine - project management software
# Copyright (C) 2006-  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require_relative '../../../../test_helper'
require 'redmine/field_format'

class Redmine::EncryptedStringFieldFormatTest < ActionView::TestCase
  def setup
    User.current = nil
    @field = with_cipher_key do
      IssueCustomField.create!(:name => 'Secret', :field_format => 'encrypted_string',
                               :is_for_all => true, :tracker_ids => [1])
    end
  end

  def test_value_should_be_stored_encrypted
    with_cipher_key do
      issue = save_issue_with_secret('my secret')
      custom_value = CustomValue.find_by(:customized => issue, :custom_field => @field)

      assert_match /\Aaes-256-cbc:.+\z/, custom_value.read_attribute(:value)
      assert_not_includes custom_value.read_attribute(:value), 'my secret'
      assert_equal 'my secret', custom_value.value
      assert_equal 'my secret', Issue.find(issue.id).custom_field_value(@field)
    end
  end

  def test_unchanged_value_should_not_be_encrypted_again
    with_cipher_key do
      issue = save_issue_with_secret('my secret')
      stored = CustomValue.find_by(:customized => issue, :custom_field => @field).read_attribute(:value)

      issue = Issue.find(issue.id)
      issue.custom_field_values = {@field.id.to_s => 'my secret'}
      issue.subject = 'Updated'
      issue.save!

      assert_equal stored, CustomValue.find_by(:customized => issue, :custom_field => @field).read_attribute(:value)
    end
  end

  def test_journal_details_should_not_store_values
    with_cipher_key do
      issue = save_issue_with_secret('old secret')
      issue = Issue.find(issue.id)
      issue.init_journal(User.find(1))
      issue.custom_field_values = {@field.id.to_s => 'new secret'}
      issue.save!

      detail = issue.journals.last.details.detect {|d| d.prop_key == @field.id.to_s}
      assert_not_nil detail
      assert_nil detail.old_value
      assert_nil detail.value
    end
  end

  def test_custom_field_should_not_be_created_without_cipher_key
    with_cipher_key(nil) do
      field = IssueCustomField.new(:name => 'Other secret', :field_format => 'encrypted_string')
      assert_not field.save
      assert_include ::I18n.t(:error_database_cipher_key_not_configured), field.errors[:field_format]
    end
  end

  def test_custom_field_should_not_be_visible_without_cipher_key
    issue = with_cipher_key {save_issue_with_secret('my secret')}

    with_cipher_key(nil) do
      issue = Issue.find(issue.id)
      admin = User.find(1)
      assert_not @field.visible_by?(issue.project, admin)
      assert_not_include @field, issue.visible_custom_field_values(admin).map(&:custom_field)
      assert_not_include @field, issue.editable_custom_fields(admin)
      assert_nil issue.custom_field_value(@field)
    end
  end

  def test_stored_value_should_be_kept_without_cipher_key
    issue = with_cipher_key {save_issue_with_secret('my secret')}
    stored = CustomValue.find_by(:customized => issue, :custom_field => @field).read_attribute(:value)

    with_cipher_key(nil) do
      issue = Issue.find(issue.id)
      issue.init_journal(User.find(1))
      issue.safe_attributes = {'subject' => 'Updated', 'custom_field_values' => {@field.id.to_s => 'other'}}
      issue.save!
    end

    assert_equal stored, CustomValue.find_by(:customized => issue, :custom_field => @field).read_attribute(:value)
    with_cipher_key {assert_equal 'my secret', Issue.find(issue.id).custom_field_value(@field)}
  end

  def test_value_should_be_nil_with_wrong_cipher_key
    issue = with_cipher_key {save_issue_with_secret('my secret')}
    stored = CustomValue.find_by(:customized => issue, :custom_field => @field).read_attribute(:value)

    with_cipher_key('wrong') do
      issue = Issue.find(issue.id)
      assert_nil issue.custom_field_value(@field)

      issue.subject = 'Updated'
      issue.save!
    end

    assert_equal stored, CustomValue.find_by(:customized => issue, :custom_field => @field).read_attribute(:value)
  end

  def test_value_should_be_encrypted_by_encrypt_all
    issue = with_cipher_key(nil) {save_issue_with_secret('my secret')}
    custom_value = CustomValue.find_by(:customized => issue, :custom_field => @field)
    custom_value.update_column(:value, 'my secret')

    with_cipher_key do
      assert CustomValue.where(:id => custom_value.id).encrypt_all(:value)
      assert_match /\Aaes-256-cbc:/, custom_value.reload.read_attribute(:value)
      assert_equal 'my secret', custom_value.value

      assert CustomValue.where(:id => custom_value.id).decrypt_all(:value)
      assert_equal 'my secret', custom_value.reload.read_attribute(:value)
    end
  end

  def test_value_of_other_formats_should_not_be_decrypted
    field = IssueCustomField.create!(:name => 'Text', :field_format => 'string')
    custom_value = CustomValue.new(:custom_field => field, :value => 'aes-256-cbc:foo')

    with_cipher_key do
      assert_equal 'aes-256-cbc:foo', custom_value.value
    end
  end

  def test_format_should_not_support_filter_sort_and_bulk_edit
    assert_not @field.format.is_filter_supported
    assert_not @field.format.searchable_supported
    assert_not @field.format.bulk_edit_supported
    assert_nil @field.order_statement
    assert_nil @field.group_statement
  end

  def test_edit_tag_should_not_render_stored_value
    custom_value = CustomFieldValue.new(:custom_field => @field, :customized => Issue.new)
    custom_value.instance_variable_set(:@value, 'my secret')
    custom_value.value_was = 'my secret'

    html = @field.format.edit_tag(self, 'issue_custom_field_values_1', 'issue[custom_field_values][1]', custom_value)
    assert_select_in html, 'input[type=password][name=ignore][value=?]', 'x' * 15
    assert_not_includes html, 'my secret'
  end

  def test_edit_tag_without_stored_value
    custom_value = CustomFieldValue.new(:custom_field => @field, :customized => Issue.new, :value => '')

    html = @field.format.edit_tag(self, 'issue_custom_field_values_1', 'issue[custom_field_values][1]', custom_value)
    assert_select_in html, 'input[type=password][name=?]', 'issue[custom_field_values][1]'
  end

  private

  def with_cipher_key(key='secret')
    result = nil
    Redmine::Configuration.with('database_cipher_key' => key) {result = yield}
    result
  end

  def save_issue_with_secret(secret)
    issue = Issue.new(:project_id => 1, :tracker_id => 1, :author_id => 1, :subject => 'Secret')
    issue.custom_field_values = {@field.id.to_s => secret}
    issue.save!
    issue
  end
end
