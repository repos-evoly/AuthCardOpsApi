using System.ComponentModel.DataAnnotations;

namespace AuthCardOpsApi.Core.Dtos
{
    public class EnableTwoFactorDto
    {
        [Required]
        public string? Email { get; set; }
    }
}
