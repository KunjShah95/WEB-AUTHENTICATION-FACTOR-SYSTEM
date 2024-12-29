require 'bcrypt'
require 'jwt'
require 'securerandom'
require 'rotp'
require 'json'

module WebAuthenticationSystem
  class User
    attr_accessor :failed_attempts, :locked_until
    attr_reader :id, :email, :password_hash, :two_factor_secret, :recovery_codes
    
    def initialize(id, email, password_hash, two_factor_secret)
      @id = id
      @email = email
      @password_hash = password_hash
      @failed_attempts = 0
      @locked_until = nil
      @two_factor_secret = two_factor_secret
      @recovery_codes = []
      generate_recovery_codes
    end

    def generate_recovery_codes
      @recovery_codes = Array.new(10) { SecureRandom.hex(10) }
    end
  end

  class AuthenticationError < StandardError; end

  class Authentication
    def initialize
      @jwt_secret = ENV['JWT_SECRET'] || 'default_jwt_secret' # Ensure this is securely set in production
      @password_pepper = ENV['PASSWORD_PEPPER'] || 'default_password_pepper'
      @max_failed_attempts = 5
      @lockout_duration = 30 * 60
      @users = {} # Replace with a database in a production system
    end

    # Register a new user
    def register_user(email, password)
      validate_password_strength(password)
      validate_email_format(email)
      raise AuthenticationError, "Email already registered" if @users[email]

      password_hash = hash_password(password)
      user_id = SecureRandom.uuid
      two_factor_secret = ROTP::Base32.random
      user = User.new(user_id, email, password_hash, two_factor_secret)
      @users[email] = user

      send_email(email, "Welcome! Your 2FA secret is: #{two_factor_secret}")

      {
        user_id: user_id,
        recovery_codes: user.recovery_codes,
        two_factor_secret: two_factor_secret
      }
    end

    # Authenticate user
    def authenticate(email, password, totp_code = nil)
      user = @users[email]
      raise AuthenticationError, "User not found" unless user

      if user.locked_until && Time.now < user.locked_until
        raise AuthenticationError, "Account locked. Try again later"
      end

      unless verify_password(password, user.password_hash)
        handle_failed_attempt(user)
        raise AuthenticationError, "Invalid credentials"
      end

      user.failed_attempts = 0
      if user.two_factor_secret && totp_code
        verify_totp(user, totp_code)
      elsif user.two_factor_secret
        raise AuthenticationError, "2FA code required"
      end

      generate_token(user)
    end

    # Initiate password reset
    def initiate_password_reset(email)
      user = @users[email]
      raise AuthenticationError, "User not found" unless user

      reset_token = SecureRandom.hex(32)
      reset_token_hash = hash_password(reset_token)
      expiry = Time.now + 3600

      user.instance_variable_set(:@reset_token_hash, reset_token_hash)
      user.instance_variable_set(:@reset_expiry, expiry)

      send_email(email, "Your password reset token: #{reset_token}")
    end

    private

    def validate_password_strength(password)
      unless password.match?(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/)
        raise AuthenticationError, "Password does not meet security requirements"
      end
    end

    def validate_email_format(email)
      unless email.match?(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i)
        raise AuthenticationError, "Invalid email format"
      end
    end

    def hash_password(password)
      peppered_password = "#{password}#{@password_pepper}"
      BCrypt::Password.create(peppered_password)
    end

    def verify_password(password, hash)
      peppered_password = "#{password}#{@password_pepper}"
      BCrypt::Password.new(hash) == peppered_password
    end

    def verify_totp(user, code)
      totp = ROTP::TOTP.new(user.two_factor_secret)
      unless totp.verify(code, drift_behind: 15)
        raise AuthenticationError, "Invalid 2FA code"
      end
    end

    def handle_failed_attempt(user)
      user.failed_attempts += 1
      if user.failed_attempts >= @max_failed_attempts
        user.locked_until = Time.now + @lockout_duration
        log_security_event(user.id, 'ACCOUNT_LOCKED', 'Too many failed attempts')
      end
    end

    def generate_token(user)
      payload = {
        user_id: user.id,
        email: user.email,
        exp: Time.now.to_i + 3600
      }
      JWT.encode(payload, @jwt_secret, 'HS256')
    end

    def send_email(email, message)
      puts "Simulating email to #{email}: #{message}"
    end

    def log_security_event(user_id, event_type, details)
      event = {
        timestamp: Time.now.utc,
        user_id: user_id,
        event_type: event_type,
        details: details
      }
      puts "Security Event Logged: #{event.to_json}"
    end
  end
end
