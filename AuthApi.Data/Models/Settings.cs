using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthApi.Data.Models
{
    [Table("Settings")]
    public class Settings : Auditable
    {
        [Key]
        public int Id { get; set; }

        public bool IsTwoFactorAuthEnabled { get; set; } 
        public bool IsRecaptchaEnabled { get; set; } 
        public string Url {get; set;}
        public string Date { get; set;}
    }
}
//ask mr ismat should settings table be key and value or the logic i used works