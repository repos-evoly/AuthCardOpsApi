using System.ComponentModel;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Data.Models
{
    [Table("Customers")]
    [Index(nameof(CustomerId), IsUnique = true, Name = "Unique_CustomerId")]
    public class Customer : Auditable
    {
        [Key]
        [MaxLength(8)]
        public string CustomerId { get; set; }

        [ForeignKey("User")]
        public int UserId { get; set; }

        public User User { get; set; }

        [MaxLength(25)]
        public string NationalId { get; set; }

        public DateTime? BirthDate { get; set; }

        [MaxLength(225)]
        public string Address { get; set; }
   
        [MaxLength(225)]
        public string Phone { get; set; }

        [DefaultValue("Pending")]
        public string KycStatus { get; set; }
    }
}
