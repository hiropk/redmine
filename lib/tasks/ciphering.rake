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


namespace :db do
  encrypted_custom_values = lambda do
    CustomValue.where(:custom_field_id => CustomField.where(:field_format => 'encrypted_string').select(:id))
  end

  desc 'Encrypts SCM and LDAP passwords and encrypted custom field values in the database.'
  task :encrypt => :environment do
    unless (Repository.encrypt_all(:password) &&
      AuthSource.encrypt_all(:account_password) &&
      User.encrypt_all(:twofa_totp_key) &&
      encrypted_custom_values.call.encrypt_all(:value))
      raise "Some objects could not be saved after encryption, update was rolled back."
    end
  end

  desc 'Decrypts SCM and LDAP passwords and encrypted custom field values in the database.'
  task :decrypt => :environment do
    if encrypted_custom_values.call.any?(&:value_undecryptable?)
      raise "Some encrypted custom field values could not be decrypted, check the database_cipher_key."
    end
    unless (Repository.decrypt_all(:password) &&
      AuthSource.decrypt_all(:account_password) &&
      User.decrypt_all(:twofa_totp_key) &&
      encrypted_custom_values.call.decrypt_all(:value))
      raise "Some objects could not be saved after decryption, update was rolled back."
    end
  end
end
