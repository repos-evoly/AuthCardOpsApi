
using AuthApi.Core.Dtos;

namespace AuthApi.Core.Abstractions
{
  public interface IStaticDataRepository
  {
    public IEnumerable<RoleDto> GetRoles();
  }
}
