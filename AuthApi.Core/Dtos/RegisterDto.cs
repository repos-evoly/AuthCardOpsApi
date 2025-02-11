using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
    public class RegisterDto
    {
        [Required]
        public string FullNameAR { get; set; }

        [Required]
        public string FullNameLT { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [MinLength(6)]
        public string Password { get; set; }

        [Required]
        public int RoleId { get; set; } 

        
    }
}
