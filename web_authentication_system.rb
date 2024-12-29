require 'bcrypt'
require 'jwt'
require 'securerandom'
require 'rotp'
require 'json'
require 'rack/utils'

module WebAuthenticationSystem
  class User
    attr_accessor :failed_attempts, :locked_until, :reset_token_hash, :reset_expiry
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
      @jwt_secret = ENV['JWT_SECRET'] || 'default_jwt_secret'
      @password_pepper = ENV['PASSWORD_PEPPER'] || 'default_password_pepper'
      @max_failed_attempts = 5
      @lockout_duration = 30 * 60
      @rate_limit = {}
      @rate_limit_window = 60
      @max_requests_per_window = 100
      @users = Hash.new { |hash, key| hash[key] = nil }
      @csrf_tokens = {}
    end

    # Rate limiting
    def rate_limit(ip_address)
      current_time = Time.now.to_i
      @rate_limit[ip_address] ||= []
      @rate_limit[ip_address].reject! { |timestamp| timestamp < current_time - @rate_limit_window }
      if @rate_limit[ip_address].size >= @max_requests_per_window
        raise AuthenticationError, "Rate limit exceeded. Try again later."
      end
      @rate_limit[ip_address] << current_time
    end

    # Input validation and sanitization
    def validate_and_sanitize_input(input)
      sanitized_input = Rack::Utils.escape_html(input)
      raise AuthenticationError, "Invalid input detected." unless sanitized_input == input
      sanitized_input
    end

    # Register a user
    def register_user(email, password)
      sanitized_email = validate_and_sanitize_input(email)
      validate_password_strength(password)
      validate_email_format(sanitized_email)
      raise AuthenticationError, "Email already registered" if @users[sanitized_email]

      password_hash = hash_password(password)
      user_id = SecureRandom.uuid
      two_factor_secret = ROTP::Base32.random
      user = User.new(user_id, sanitized_email, password_hash, two_factor_secret)
      @users[sanitized_email] = user

      send_email(sanitized_email, "Welcome! Your 2FA secret is: #{two_factor_secret}")

      {
        user_id: user_id,
        recovery_codes: user.recovery_codes,
        two_factor_secret: two_factor_secret
      }
    end

    # Generate CSRF token
    def generate_csrf_token
      token = SecureRandom.hex(32)
      @csrf_tokens[token] = Time.now + 3600 # 1-hour expiry
      token
    end

    # Validate CSRF token
    def validate_csrf_token(token)
      raise AuthenticationError, "Invalid CSRF token" unless @csrf_tokens[token] && @csrf_tokens[token] > Time.now
      @csrf_tokens.delete(token)
    end

    # Secure HTTP headers
    def secure_http_headers
      {
        'Strict-Transport-Security' => 'max-age=63072000; includeSubDomains',
        'X-Frame-Options' => 'DENY',
        'X-Content-Type-Options' => 'nosniff',
        'Content-Security-Policy' => "default-src 'self'",
        'Referrer-Policy' => 'no-referrer'
      }
    end

    # Authenticate user
    def authenticate(email, password, totp_code = nil, ip_address = nil)
      rate_limit(ip_address) if ip_address
      sanitized_email = validate_and_sanitize_input(email)
      user = @users[sanitized_email]
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
      # Implement actual email sending logic here
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
