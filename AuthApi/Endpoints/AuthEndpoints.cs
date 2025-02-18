using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http;
using QRCoder;
using OtpNet;
using AuthApi.Data.Context;
using AuthApi.Data.Models;
using AuthApi.Core.Dtos;
using AuthApi.Abstractions;
using AuthApi.Core.Abstractions;

namespace AuthApi.Endpoints
{
    public class AuthEndpoints : IEndpoints
    {
        public void RegisterEndpoints(WebApplication app)
        {
            var auth = app.MapGroup("/api/auth");
            auth.MapPost("/register", Register);
            auth.MapPost("/login", Login);
            auth.MapPost("/enable-2fa", EnableTwoFactorAuthentication);
            auth.MapPost("/verify-2fa", VerifyTwoFactorAuthentication);
            auth.MapPost("/forgot-password", ForgotPassword);
            auth.MapPost("/reset-password", ResetPassword);
            auth.MapPost("/refresh-token", RefreshToken);
            auth.MapPost("/logout", Logout);
        }

        /// <summary> User Registration </summary>
       public static async Task<IResult> Register( AuthApiDbContext db, RegisterDto registerDto)
        {
            if (await db.Users.AnyAsync(u => u.Email == registerDto.Email))
                return TypedResults.BadRequest("User already exists.");

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(registerDto.Password);

            var role = await db.Roles.FirstOrDefaultAsync(r => r.Id == registerDto.RoleId);
            if (role == null) return TypedResults.BadRequest("Invalid role. Please select a valid role.");

            var user = new User
            {
                FullNameAR = registerDto.FullNameAR,
                FullNameLT = registerDto.FullNameLT,
                Email = registerDto.Email,
                Password = hashedPassword,
                RoleId = role.Id,
                Active = true
            };

            db.Users.Add(user);
            await db.SaveChangesAsync();
            //ask mr ismat what to return 
            return TypedResults.Ok(new { Message = "User registered successfully.", UserId = user.Id });
        }


        /// <summary> Login with JWT </summary>
        /// Ask Mr ismat about Login and 2fa logic cases like if settings table has 2fa off but user has enabled 2fa will it ask him?? if settings has 2fa on it should force all users to enable 2fa? 
       public static async Task<IResult> Login(AuthApiDbContext db, IConfiguration config, HttpContext httpContext, LoginDto loginDto)
        {
            var jwtSection = config.GetSection("Jwt");

            if (string.IsNullOrEmpty(loginDto.Email) || string.IsNullOrEmpty(loginDto.Password))
                return TypedResults.NotFound("Invalid Credentials!");

            var user = await db.Users
                .Include(u => u.UserSecurity)
                .Include(u => u.Role)
                .FirstOrDefaultAsync(u => u.Email == loginDto.Email);

            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.Password))
                return TypedResults.NotFound("Invalid Credentials!");

            var settings = await db.Settings.FirstOrDefaultAsync();
            bool isGlobal2FAEnabled = settings?.IsTwoFactorAuthEnabled ?? false;

            // 🔹 If 2FA is required globally and the user has it enabled, return "RequiresTwoFactor"
            if (isGlobal2FAEnabled)
            {
                if (user.UserSecurity == null || !user.UserSecurity.IsTwoFactorEnabled)
                {
                    return TypedResults.Ok("Two-Factor Authentication is required. Please enable 2FA to proceed.");
                }

                return TypedResults.Ok(new { RequiresTwoFactor = true });
            }

            
            var accessToken = GenerateJwtToken(user, config);
            var refreshToken = GenerateRefreshToken();

            
            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.RefreshToken = refreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.UtcNow.AddDays(30);

            await db.SaveChangesAsync();

            return TypedResults.Ok(new 
            { 
                AccessToken = accessToken,
                RefreshToken = refreshToken 
            });
        }





        /// <summary> Enable Google Authenticator 2FA </summary>
        /// <summary> Enable Google Authenticator 2FA and save QR code </summary>
       public static async Task<IResult> EnableTwoFactorAuthentication(
            AuthApiDbContext db, 
            IQrCodeRepository qrCodeRepository, 
            EnableTwoFactorDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user == null) return TypedResults.NotFound("User not found.");

            using var generator = RandomNumberGenerator.Create();
            byte[] secretKeyBytes = KeyGeneration.GenerateRandomKey(20); 
            string base32Secret = Base32Encoding.ToString(secretKeyBytes).TrimEnd('='); 


            
            string qrCodeFileName = await qrCodeRepository.GenerateAndSaveQrCodeAsync(user.Email, base32Secret);

            if (user.UserSecurity == null)
            {
                user.UserSecurity = new UserSecurity
                {
                    UserId = user.Id,
                    TwoFactorSecretKey = base32Secret, 
                    IsTwoFactorEnabled = true,
                    PasswordResetToken = null,
                    PasswordResetTokenExpiry = null
                };
                db.UserSecurities.Add(user.UserSecurity);
            }
            else
            {
                user.UserSecurity.TwoFactorSecretKey = base32Secret;
                user.UserSecurity.IsTwoFactorEnabled = true;
            }

            await db.SaveChangesAsync();

            return TypedResults.Ok(new
            {
                SecretKey = base32Secret,
                QrCodePath = $"/attachments/{qrCodeFileName}"
            });
        }



        /// <summary> Verify Google Authenticator 2FA </summary>
        public static async Task<IResult> VerifyTwoFactorAuthentication( AuthApiDbContext db,  IConfiguration config,  VerifyTwoFactorDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity)
                                    .FirstOrDefaultAsync(u => u.Email == dto.Email);

            if (user == null || user.UserSecurity?.IsTwoFactorEnabled != true)
                return TypedResults.BadRequest("2FA is not enabled for this user.");

            if (string.IsNullOrEmpty(user.UserSecurity.TwoFactorSecretKey))
                return TypedResults.BadRequest("2FA secret key is missing.");

            bool isValidOtp = VerifyOtp(dto.Token, user.UserSecurity.TwoFactorSecretKey);

            if (!isValidOtp)
                return TypedResults.Unauthorized(); 

            var token = GenerateJwtToken(user, config);
            return TypedResults.Ok(new { Token = token });
        }

        /// <summary> Forgot Password (Request Password Reset) </summary>
        public static async Task<IResult> ForgotPassword( AuthApiDbContext db,  ForgotPasswordDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity).FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null) return TypedResults.NotFound("User not found.");

            user.UserSecurity ??= new UserSecurity { UserId = user.Id };
            user.UserSecurity.PasswordResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            user.UserSecurity.PasswordResetTokenExpiry = DateTime.UtcNow.AddMinutes(30);

            await db.SaveChangesAsync();

            return TypedResults.Ok("Password reset token sent.");
        }

        /// <summary> Reset Password </summary>
        public static async Task<IResult> ResetPassword( AuthApiDbContext db,  ResetPasswordDto dto)
        {
            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.UserSecurity.PasswordResetToken == dto.PasswordToken &&
                                          u.UserSecurity.PasswordResetTokenExpiry > DateTime.UtcNow);

            if (user == null) return TypedResults.BadRequest("Invalid or expired token.");

            // Hash the new password
            user.Password = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            // Clear the reset token
            user.UserSecurity.PasswordResetToken = null;
            user.UserSecurity.PasswordResetTokenExpiry = null;

            await db.SaveChangesAsync();

            return TypedResults.Ok("Password reset successful.");
        }

        public static async Task<IResult> Logout(AuthApiDbContext db, HttpContext httpContext)
        {
            if (!httpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
                return TypedResults.BadRequest("Refresh token is missing");

            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.UserSecurity!.RefreshToken == refreshToken);

            if (user != null)
            {
                user.UserSecurity.RefreshToken = null;
                user.UserSecurity.RefreshTokenExpiry = null;
                await db.SaveChangesAsync();
            }

            httpContext.Response.Cookies.Delete("authToken");
            httpContext.Response.Cookies.Delete("refreshToken");

            return TypedResults.Ok("Logged out successfully.");
        }


        private static string GenerateJwtToken(User user, IConfiguration config)
        {

            var jwtSection = config.GetSection("Jwt");
            var key = Encoding.UTF8.GetBytes(jwtSection["Key"]);
            var tokenHandler = new JwtSecurityTokenHandler();

            //ask mr ismat what to include in token 
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.FullNameAR),
                new Claim(ClaimTypes.GivenName, user.FullNameLT),
                new Claim(ClaimTypes.Uri, user.Image ?? ""),
                new Claim(ClaimTypes.Role, user.Role?.TitleLT ?? "Unassigned"),
                new Claim(ClaimTypes.GroupSid, user.BranchId ?? ""),
                new Claim(ClaimTypes.Sid, user.Id.ToString())
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = jwtSection["Issuer"],
                Audience = jwtSection["Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static async Task<IResult> RefreshToken(AuthApiDbContext db, IConfiguration config, HttpContext httpContext)
        {
            if (!httpContext.Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
                return TypedResults.BadRequest("Refresh token is missing");

            var user = await db.Users.Include(u => u.UserSecurity)
                .FirstOrDefaultAsync(u => u.UserSecurity!.RefreshToken == refreshToken &&
                                        u.UserSecurity.RefreshTokenExpiry > DateTime.UtcNow);

            if (user == null)
                return TypedResults.Unauthorized();

            var newAccessToken = GenerateJwtToken(user, config);
            var newRefreshToken = GenerateRefreshToken();

            user.UserSecurity.RefreshToken = newRefreshToken;
            user.UserSecurity.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
            await db.SaveChangesAsync();

            httpContext.Response.Cookies.Append("authToken", newAccessToken, new CookieOptions
            {
                Expires = DateTime.UtcNow.AddMinutes(30),
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            httpContext.Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                Expires = DateTime.UtcNow.AddDays(7),
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            return TypedResults.Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
        }



        private static bool VerifyOtp(string otp, string secretKey)
        {
            try
            {
               
                byte[] keyBytes = Base32Encoding.ToBytes(secretKey);

                var totp = new Totp(keyBytes, step: 30, totpSize: 6, mode: OtpHashMode.Sha1);

                bool isValid = totp.VerifyTotp(otp, out _, new VerificationWindow(previous: 1, future: 1));

                Console.WriteLine($"[DEBUG] OTP Received: {otp}");
                Console.WriteLine($"[DEBUG] Secret Key Used: {secretKey}");
                Console.WriteLine($"[DEBUG] OTP Valid: {isValid}");

                return isValid;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] OTP Verification Failed: {ex.Message}");
                return false;
            }
        }

        private static async Task<bool> VerifyRecaptcha(string secretKey, string recaptchaToken)
        {
            using var client = new HttpClient();
            var response = await client.PostAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={recaptchaToken}",
                null);

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var result = System.Text.Json.JsonSerializer.Deserialize<RecaptchaResponse>(jsonResponse);
            return result?.Success ?? false;
        }

        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public double Score { get; set; }
            public string Action { get; set; }
            public string[] ErrorCodes { get; set; }
        }

        public static async Task<IResult> GetRecaptchaSettings(AuthApiDbContext db)
        {
            var settings = await db.Settings.FirstOrDefaultAsync();
            return settings != null
                ? TypedResults.Ok(new { SiteKey = settings.RecaptchaSiteKey })
                : TypedResults.NotFound("No settings found.");
        }

      

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }



    }
}
