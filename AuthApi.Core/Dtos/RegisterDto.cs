using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
    public class RegisterDto
    {
        [Required]
        public required string FullNameAR { get; set; }

        [Required]
        public required string FullNameLT { get; set; }

        [Required]
        [EmailAddress]
        public required string Email { get; set; }

        [Required]
        [MinLength(6)]
        public required string Password { get; set; }

        [Required]
        public int RoleId { get; set; } 

        
    }
}
