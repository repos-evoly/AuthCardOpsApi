using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Data.Models
{
    [Table("Users")]
    [Index(nameof(Email), IsUnique = true, Name = "Unique_Email")]
    public class User : Auditable
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(150)]
        public string FullNameAR { get; set; }

        [MaxLength(150)]
        public string FullNameLT { get; set; }

        [MaxLength(150)]
        public string Email { get; set; }

        public string Password { get; set; }

        public string Image { get; set; }

        public string PasswordToken { get; set; }

        [DefaultValue(true)]
        public bool Active { get; set; }

        [MaxLength(10)]
        public string BranchId { get; set; }

        [DefaultValue(1)] 
        public int RoleId { get; set; }  

        public Role Role { get; set; }

        public UserSecurity UserSecurity { get; set; }

        public Customer Customer { get; set; }  // Null if Employee
        public Employee Employee { get; set; }  // Null if Customer
    }
}
