using System.ComponentModel.DataAnnotations;

namespace AuthCardOpsApi.Core.Dtos
{
    public class EditRoleDto
    {
        [Required]
        [MaxLength(50)]
        public string? TitleAR { get; set; }
        public string? TitleLT { get; set; }
    }
}
