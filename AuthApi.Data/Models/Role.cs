using System.ComponentModel;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Data.Models
{
    [Table("Role")]
    public class Role : Auditable
    {
        [Key]
        public int Id { get; set; }

        [MaxLength(100)]
        public string TitleAR { get; set; }
        [Required]
        public string TitleLT { get; set; }
        public ICollection<User> Users { get; set; }
    }
}
