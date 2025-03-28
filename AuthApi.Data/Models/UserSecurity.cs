using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Data.Models
{
    [Table("UserSecurity")]
    public class UserSecurity
    {
        [Key]
        public int Id { get; set; }

        [ForeignKey(nameof(User))]
        public int UserId { get; set; }

        public User? User { get; set; } // Nullable

        public string? TwoFactorSecretKey { get; set; } // Nullable
        public bool IsTwoFactorEnabled { get; set; }
        public string? PasswordResetToken { get; set; } // Nullable
        public DateTime? PasswordResetTokenExpiry { get; set; }
        public string? QrCodePath { get; set; } // Nullable
        public string? RefreshToken { get; set; } // Nullable
        public DateTime? RefreshTokenExpiry { get; set; }
        public DateTime? LastLogin { get; set; }
        public DateTime? LastLogout { get; set; }
    }
}
