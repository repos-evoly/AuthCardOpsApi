using System.ComponentModel;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Data.Models
{
    [Table("Employees")]
    [Index(nameof(EmployeeCode), IsUnique = true, Name = "Unique_EmployeeCode")]
    public class Employee : Auditable
    {
        [Key]
        public int EmployeeId { get; set; }

        [ForeignKey("User")]
        public int UserId { get; set; }

        public User User { get; set; }

        [MaxLength(25)]
        public string EmployeeCode { get; set; }

        [MaxLength(225)]
        public string Department { get; set; }

        [MaxLength(225)]
        public string Position { get; set; }

        [MaxLength(225)]
        public string Phone { get; set; }

        [MaxLength(225)]
        public string Email { get; set; }

        [DefaultValue(true)]
        public bool Active { get; set; }
    }
}
