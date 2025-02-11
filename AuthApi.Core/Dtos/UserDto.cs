namespace AuthApi.Core.Dtos
{

  public class EditUserDto
  {
    public string FullNameAR { get; set; }
    public string FullNameLT { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
    public string Image { get; set; }
    public bool Active { get; set; }
    public string RoleId { get; set; }
    public string BranchId { get; set; }
    public string PasswordToken { get; set; }
  }

  public class UserDto : EditUserDto
  {
    public int Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
  }

}