using System.ComponentModel.DataAnnotations;

namespace AuthCardOpsApi.Core.Dtos
{
    public class VerifyTwoFactorDto
    {
        [Required]
        public required string Email { get; set; }

        [Required]
        public required string Token { get; set; }
    }
}
