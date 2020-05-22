# frozen_string_literal: true

module DeviseTokenAuth::Concerns::UserOmniauthCallbacks
  extend ActiveSupport::Concern

  included do
    validates self.authentication_keys.first, presence: true,if: :email_provider?
    if self.authentication_keys.first == :email
      validates self.authentication_keys.first, :devise_token_auth_email => true, allow_nil: true, allow_blank: true, if: :email_provider?
    end
    validates_presence_of :uid, unless: :email_provider?

    # only validate unique emails among email registration users
    validates self.authentication_keys.first, uniqueness: { case_sensitive: false, scope: [ :provider ] + DeviseTokenAuth.multitenancy_scope_fields }, on: :create, if: :email_provider?

    # keep uid in sync with email
    before_save :sync_uid
    before_create :sync_uid
  end

  protected

  def email_provider?
    provider == 'email'
  end

  def sync_uid
    self.uid = self.send(self.class.authentication_keys.first.to_sym) if email_provider?
  end
end
