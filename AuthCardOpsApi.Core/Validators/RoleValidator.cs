using AuthCardOpsApi.Core.Dtos;
using FluentValidation;

namespace AuthCardOpsApi.Validators;

public class RoleValidator : AbstractValidator<EditRoleDto>
{
  public RoleValidator()
  {
    // RuleFor(u => u.Id).NotNull().NotEmpty().MinimumLength(3);
    RuleFor(u => u.TitleAR).NotNull().NotEmpty().MinimumLength(3);
    RuleFor(u => u.TitleLT).NotNull().NotEmpty().MinimumLength(3);
  }
}