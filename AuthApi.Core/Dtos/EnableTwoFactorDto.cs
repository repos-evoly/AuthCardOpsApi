using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
    public class EnableTwoFactorDto
    {
        [Required]
        public string Email { get; set; }
    }
}
 