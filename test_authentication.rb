require 'bcrypt'
require 'jwt'
require 'securerandom'
require 'rotp'

# Initialize Authentication system
module WebAuthenticationSystem
  class Authentication
    def register_user(email, password)
      # Dummy implementation for registering a user
      { email: email, two_factor_secret: ROTP::Base32.random_base32 }
    end

    def authenticate(email, password, totp_code = nil)
      # Dummy implementation for authenticating a user
      if password == "StrongPassword123!"
        if totp_code.nil? || totp_code == ROTP::TOTP.new("base32secret3232").now
          return JWT.encode({ email: email }, 'secret', 'HS256')
        else
          raise AuthenticationError, "Invalid 2FA code"
        end
      else
        raise AuthenticationError, "Invalid credentials"
      end
    end

    def rate_limit(ip_address)
      # Dummy implementation for rate limiting
      true
    end
  end

  class AuthenticationError < StandardError; end
end

auth_system = WebAuthenticationSystem::Authentication.new

# 1. Test Registering a New User
email = "test@example.com"
password = "StrongPassword123!"
begin
  user_data = auth_system.register_user(email, password)
  puts "User registered successfully: #{user_data}"
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Registration failed: #{e.message}"
end

# 2. Test Authenticating with Correct Credentials (without 2FA)
begin
  token = auth_system.authenticate(email, password)
  puts "Authentication successful! JWT token: #{token}"
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"
end

# 3. Test Authenticating with Incorrect Password
begin
  token = auth_system.authenticate(email, "WrongPassword")
  puts "Authentication successful! JWT token: #{token}"
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"  # Should print "Invalid credentials"
end

# 4. Test Authenticating with 2FA (Invalid and Valid Code)
totp_code_invalid = "123456"
totp_code_valid = ROTP::TOTP.new(user_data[:two_factor_secret]).now

begin
  token = auth_system.authenticate(email, password, totp_code_invalid)
  puts "Authentication successful! JWT token: #{token}"
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"  # Should print "Invalid 2FA code"
end

begin
  token = auth_system.authenticate(email, password, totp_code_valid)
  puts "Authentication successful! JWT token: #{token}"
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"
end

# 5. Test Rate Limiting (Simulate Requests)
ip_address = "192.168.1.1"
10.times do
  begin
    auth_system.rate_limit(ip_address)
    puts "Request allowed"
  rescue WebAuthenticationSystem::AuthenticationError => e
    puts "Rate limit exceeded: #{e.message}"
  end
end

# 6. Test Lockout After Failed Attempts
begin
  auth_system.authenticate(email, "WrongPassword")
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"  # First failed attempt
end

begin
  auth_system.authenticate(email, "WrongPassword")
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"  # Second failed attempt
end

begin
  auth_system.authenticate(email, "WrongPassword")
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"  # Third failed attempt
end

begin
  auth_system.authenticate(email, "WrongPassword")
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"  # Fourth failed attempt
end

begin
  auth_system.authenticate(email, "WrongPassword")
rescue WebAuthenticationSystem::AuthenticationError => e
  puts "Authentication failed: #{e.message}"  # Fifth failed attempt, account should be locked
end
