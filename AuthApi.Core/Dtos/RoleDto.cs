using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
     public class RoleDto
    {
        public int Id { get; set; }
        public string? TitleLt { get; set; }

        public string? TitleAR { get; set; }

    }
}
