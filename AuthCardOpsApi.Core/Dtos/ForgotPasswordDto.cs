using System.ComponentModel.DataAnnotations;

namespace AuthCardOpsApi.Core.Dtos
{
    public class ForgotPasswordDto
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
    }
}
