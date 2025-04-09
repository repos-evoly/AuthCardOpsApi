using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace AuthCardOpsApi.Data.Models
{
    [Table("Users")]
    [Index(nameof(Email), IsUnique = true, Name = "Unique_Email")]
    public class User : Auditable
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(150)]
        public string Email { get; set; } = string.Empty; // Initialized

        public string Password { get; set; } = string.Empty; // Initialized

        public string? PasswordToken { get; set; } // Nullable

        [DefaultValue(true)]
        public bool Active { get; set; }

        [MaxLength(10)]
        public string? BranchId { get; set; } // Nullable

        [DefaultValue(1)]
        public int RoleId { get; set; }

        public Role? Role { get; set; } // Nullable

        public required UserSecurity UserSecurity { get; set; } // Nullable
    }
}
