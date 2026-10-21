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

class CustomValue < ApplicationRecord
  include Redmine::Ciphering

  belongs_to :custom_field
  belongs_to :customized, :polymorphic => true

  before_save :encrypt_clear_value
  after_save :custom_field_after_save_custom_value

  def initialize(attributes=nil, *args)
    super
    if new_record? && custom_field && !attributes.key?(:value) && (customized.nil? || customized.set_custom_field_default?(self))
      self.value ||= custom_field.default_value
    end
  end

  # Returns true if the boolean custom value is true
  def true?
    self.value == '1'
  end

  def editable?
    custom_field.editable?
  end

  def visible?(user=User.current)
    if custom_field.visible?
      true
    elsif customized.respond_to?(:project)
      custom_field.visible_by?(customized.project, user)
    else
      false
    end
  end

  def attachments_visible?(user)
    visible?(user) && customized && customized.visible?(user)
  end

  def required?
    custom_field.is_required?
  end

  def to_s
    value.to_s
  end

  # Returns the decrypted value for encrypted custom fields, or nil if
  # it can not be decrypted (eg. the cipher key is missing or wrong)
  def value
    text = super
    # Checks the format only for ciphered texts to avoid loading the custom field
    return text unless ciphered?(text) && encrypted?
    return nil if Redmine::Ciphering.cipher_key.blank?

    clear = read_ciphered_attribute(:value).force_encoding('UTF-8')
    clear.valid_encoding? ? clear : nil
  rescue OpenSSL::Cipher::CipherError, ArgumentError
    nil
  end

  def value=(arg)
    if !encrypted?
      # The format is unknown if the value is assigned before the custom field
      @value_assigned_without_custom_field = custom_field.nil?
      super
    # Keeps the stored value if unchanged, as it would be encrypted
    # with a new IV each time
    elsif !ciphered?(self[:value]) || arg.to_s != value.to_s
      write_ciphered_attribute(:value, arg)
    end
  end

  def value_undecryptable?
    encrypted? && ciphered?(self[:value]) && value.nil?
  end

  private

  def encrypted?
    custom_field&.field_format == 'encrypted_string'
  end

  def ciphered?(text)
    text.to_s.start_with?('aes-256-cbc:')
  end

  # Encrypts a value that was assigned before the custom field (eg. by
  # CustomValue.new(:value => 'x', :custom_field => field)), and refuses
  # to store it in clear text if the cipher key is missing
  def encrypt_clear_value
    return unless @value_assigned_without_custom_field && encrypted?

    @value_assigned_without_custom_field = false
    return if self[:value].blank? || ciphered?(self[:value])

    throw :abort if Redmine::Ciphering.cipher_key.blank?

    write_ciphered_attribute(:value, self[:value])
  end

  def custom_field_after_save_custom_value
    custom_field.after_save_custom_value(self)
  end
end
