using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
    public class ForgotPasswordDto
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
    }
}
