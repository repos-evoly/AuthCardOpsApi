using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
    public class VerifyTwoFactorDto
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Token { get; set; }
    }
}
