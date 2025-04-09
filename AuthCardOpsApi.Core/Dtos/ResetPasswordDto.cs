using System.ComponentModel.DataAnnotations;

namespace AuthCardOpsApi.Core.Dtos
{
  public class ResetPasswordDto
  {
    public string? PasswordToken { get; set; }
    [Required, MinLength(6)]
    public string? Password { get; set; }
    [Required, MinLength(6), Compare("Password")]
    public string? ConfirmPassword { get; set; }
  }
}
