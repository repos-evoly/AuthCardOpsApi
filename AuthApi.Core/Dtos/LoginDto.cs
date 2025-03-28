using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
    public class LoginDto
    {
        [Required]
        public string? Email { get; set; }

        [Required]
        public string? Password { get; set; }

        public string? RecaptchaToken { get; set; }
    }
}
 