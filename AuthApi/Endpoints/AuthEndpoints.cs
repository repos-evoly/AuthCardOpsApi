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
        public static async Task<IResult> Login( AuthApiDbContext db,  IConfiguration config, HttpContext httpContext,  LoginDto loginDto)
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

            if (user.Role == null)
                return TypedResults.BadRequest("User does not have a role assigned!");

            if (user.UserSecurity?.IsTwoFactorEnabled == true)
                return TypedResults.Ok(new { RequiresTwoFactor = true });

            var token = GenerateJwtToken(user, config);

            //as mr ismat if what is inder this is needed
            httpContext.Response.Cookies.Append("authToken", token, new CookieOptions
            {
                Expires = DateTime.UtcNow.AddDays(7),
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });
            //ask mr ismat what to return, token , encrypted profile, ....
            return TypedResults.Ok(token);

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
                QrCodePath = $"/api/auth/attachments/{qrCodeFileName}"
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
            user.UserSecurity.PasswordResetToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
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
                new Claim(ClaimTypes.Role, user.Role.TitleLT),
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

        
    }
}
