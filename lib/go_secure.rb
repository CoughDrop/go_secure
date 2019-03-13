require 'openssl'
require 'base64'
require 'oj'

module GoSecure
  def self.sha512(str, salt, encryption_key=nil)
    Digest::SHA512.hexdigest(str.to_s + salt.to_s + (encryption_key || self.encryption_key))
  end
  
  def self.hmac(str, salt, level, encryption_key=nil)
    # level is here so we can upgrade in the future without breaking backwards compatibility
    raise "invalid level" unless level == 1
    digest = OpenSSL::Digest::SHA512.new(encryption_key || self.encryption_key)
    res = Base64.urlsafe_encode64(OpenSSL::PKCS5.pbkdf2_hmac(str.to_s, salt.to_s, 100000, digest.digest_length, digest))
  end

  def self.lite_hmac(str, salt, level, encryption_key=nil)
    raise "invalid level" unless level == 1
    OpenSSL::HMAC.hexdigest('SHA512', OpenSSL::HMAC.hexdigest('SHA512', str.to_s, salt.to_s), encryption_key || self.encryption_key)
  end
  
  def self.nonce(str)
    Digest::SHA512.hexdigest(str.to_s + Time.now.to_i.to_s + rand(999999).to_s + self.encryption_key)[0, 24]
  end
  
  def self.encrypt(str, ref, encryption_key=nil)
    require 'base64'
    c = OpenSSL::Cipher.new('aes-256-cbc')
    c.encrypt
    sha = Digest::SHA2.hexdigest(ref + "_" + (encryption_key || self.encryption_key))
    c.key = sha[0..31]
    c.iv = iv = c.random_iv
    e = c.update(str)
    e << c.final
    res = [Base64.encode64(e), Base64.encode64(iv)]
    res
  end
  
  def self.decrypt(str, salt, ref, encryption_key=nil)
    require 'base64'
    c = OpenSSL::Cipher.new('aes-256-cbc')
    c.decrypt
    sha = Digest::SHA2.hexdigest(ref + "_" + (encryption_key || self.encryption_key))
    c.key = sha[0..31]
    iv = Base64.decode64(salt)

    c.iv = iv[0..15]
    d = c.update(Base64.decode64(str))
    d << c.final
    d.to_s
  end
  
  def self.generate_password(password)
    raise "password required" if password == nil || password.length == 0
    pw = {}
#     pw['hash_type'] = 'sha512'
#     pw['hash_type'] = 'bcrypt'
    pw['hash_type'] = 'pbkdf2-sha256-2'
    pw['salt'] = Digest::MD5.hexdigest(OpenSSL::Random.random_bytes(4) + Time.now.to_i.to_s + self.encryption_key + "pw" + OpenSSL::Random.random_bytes(16))
#     pw['hashed_password'] = Digest::SHA512.hexdigest(self.encryption_key + pw['salt'] + password.to_s)
#     salted = Digest::SHA256.hexdigest(self.encryption_key + pw['salt'] + password.to_s)
#     pw['hashed_password'] = BCrypt::Password.create(salted)
    digest = OpenSSL::Digest::SHA512.new(self.encryption_key)
    pw['hashed_password'] = Base64.urlsafe_encode64(OpenSSL::PKCS5.pbkdf2_hmac(password.to_s, pw['salt'], 100000, digest.digest_length, digest))
    pw
  end
  
  def self.outdated_password?(password_hash)
    return password_hash && password_hash['hash_type'] != 'pbkdf2-sha256-2'
  end
  
  def self.matches_password?(attempt, password_hash)
    if password_hash && password_hash['hash_type'] == 'sha512' && password_hash['salt']
      str = Digest::SHA512.hexdigest(self.encryption_key + password_hash['salt'] + attempt.to_s)
      res = str == password_hash['hashed_password']
      if !res && password_hash['old_passwords']
        # TODO: support for migrating to new hashing algorithms
      else
        res
      end
    elsif password_hash && password_hash['hash_type'] == 'bcrypt' && password_hash['salt']
      pw = BCrypt::Password.new(password_hash['hashed_password'])
      salted = Digest::SHA256.hexdigest(self.encryption_key + password_hash['salt'] + attempt.to_s)
      res = pw == salted
    elsif password_hash && password_hash['hash_type'] == 'pbkdf2-sha256' && password_hash['salt']
      digest = OpenSSL::Digest::SHA256.new
      str = Base64.encode64(OpenSSL::PKCS5.pbkdf2_hmac(attempt.to_s, password_hash['salt'], 100000, digest.digest_length, digest))
      res = str == password_hash['hashed_password']
    elsif password_hash && password_hash['hash_type'] == 'pbkdf2-sha256-2' && password_hash['salt']
      digest = OpenSSL::Digest::SHA512.new(self.encryption_key)
      str = Base64.urlsafe_encode64(OpenSSL::PKCS5.pbkdf2_hmac(attempt.to_s, password_hash['salt'], 100000, digest.digest_length, digest))
      res = str == password_hash['hashed_password']
    else
      false
    end
  end
  
  def self.validate_encryption_key
    if !self.encryption_key || self.encryption_key.length < 24
      raise "SECURE_ENCRYPTION_KEY env variable should be at least 24 characters"
    end
    return if !ActiveRecord::Base.connection.data_source_exists?('settings')
    config_hash = Digest::SHA1.hexdigest(self.encryption_key)
    stored_hash = Setting.get('encryption_hash')
    return if stored_hash == config_hash

    if stored_hash.nil?
      Setting.set('encryption_hash', config_hash);
    else
      raise "SECURE_ENCRYPTION_KEY env variable doesn't match the value stored in the database." +  
       " If this is intentional you can try DELETE FROM settings WHERE key='encryption_hash' to reset."
    end
  end

  def self.encryption_key
    ENV['SECURE_ENCRYPTION_KEY']
  end
  
  def self.browser_token
    # TODO: checks around whether it's actually a web browser??
    day = Time.now.strftime('%j')
    stamp = "#{Time.now.year}#{(Time.now.yday / 366.0 * 100.0).to_i.to_s.rjust(2, '0')}"
    stamp += '-' + GoSecure.sha512(stamp, 'browser_token')
  end
  
  def self.valid_browser_token_signature?(token)
    stamp, hash = token.split(/-/, 2)
    return hash == GoSecure.sha512(stamp, 'browser_token')
  end
  
  def self.valid_browser_token?(token)
    return false if !token || token.length == 0 || !token.match(/-/)
    stamp, hash = token.split(/-/, 2)
    current_stamp = "#{Time.now.year}#{(Time.now.yday / 366.0 * 100.0).to_i.to_s.rjust(2, '0')}"
    if current_stamp.to_i - stamp.to_i < (14/365.0*100.0) # 14 days?!
      return valid_browser_token_signature?(token)
    end
    false
  end
  
  module SecureJson
    def self.db_encryption(bool)
      @db_encryption = !!bool
    end
    
    def self.load(str)
      return nil unless str
      if str.match(/^\*\*/)
        Oj.load(str[2..-1], mode: :compat)
      else
        salt, secret = str.split(/--/, 2)
        Oj.load(GoSecure.decrypt(secret, salt, "secure_json"), mode: :compat)
      end
    end
  
    def self.dump(obj)
      json = Oj.dump(obj, mode: :compat)
      res = encrypted_dump(json)
      res
    end
  
    def self.encrypted_dump(json)
      if @db_encryption == false
        "**" + json
      else
        secret, salt = GoSecure.encrypt(json, "secure_json")
        salt + "--" + secret
      end
    end
  end

  module SerializeInstanceMethods
    def load_secure_object
      @secure_object_json = nil.to_json
      if self.id
        attr = read_attribute(self.class.secure_column) || (!self.respond_to?(:secure_column_value) && self.send(self.class.secure_column)) || (@secure_object.is_a?(String) && @secure_object) || nil
        if attr && attr.match(/\s*^{/)
          @secure_object = JSON.parse(attr)
        else
          @secure_object = GoSecure::SecureJson.load(attr)
        end
        @secure_object_json = @secure_object.to_json
        @loaded_secure_object = true
      end
      true
    end
    
    # If the serialized data has changed since initialize and paper_trail
    # is configured, then we need to manually mark the column as dirty
    # to make sure a proper paper_trail is maintained
    def mark_changed_secure_object_hash
      if !send("#{self.class.secure_column}_changed?")
        json = @secure_object.to_json
        if json != @secure_object_json
          send("#{self.class.secure_column}_will_change!")
        end
      end
      true
    end
    
    def persist_secure_object
      self.class.more_before_saves ||= []
      self.class.more_before_saves.each do |method|
        res = send(method)
        return false if res == false
      end
      mark_changed_secure_object_hash
      if send("#{self.class.secure_column}_changed?")
        secure = GoSecure::SecureJson.dump(@secure_object)
        @secure_object = GoSecure::SecureJson.load(secure)
        write_attribute(self.class.secure_column, secure)
      end
      true
    end
  end

  module SerializeClassMethods
    def secure_serialize(column)
      raise "only one secure column per record! (yes I'm lazy)" if self.respond_to?(:secure_column) && self.secure_column
      cattr_accessor :secure_column
      cattr_accessor :more_before_saves
      self.secure_column = column
      prepend SecureSerializeHelpers

      before_save :persist_secure_object
      define_singleton_method(:before_save) do |*args|
        raise "only simple before_save calls after secure_serialize: #{args.to_json}" unless args.length == 1 && args[0].is_a?(Symbol)
        self.more_before_saves ||= []
        self.more_before_saves << args[0]
      end
      define_method("secure_column_value") do
        nil
      end
      define_method("#{column}") do
        load_secure_object unless @loaded_secure_object 
        @secure_object
      end
      define_method("#{column}=") do |val|
        @loaded_secure_object = true
        @secure_object = val
      end
      # Commented out because eager-loading an encrypted data column is not efficient
      # after_initialize :load_secure_object
    end
  end

  module SecureSerializeHelpers
    def reload(*args)
      res = super
      load_secure_object
      res
    end
    
    def []=(*args)
      if args[0].to_s == self.class.secure_column
        send("#{self.class.secure_column}=", args[1])
      else
        super
      end
    end
  end
end