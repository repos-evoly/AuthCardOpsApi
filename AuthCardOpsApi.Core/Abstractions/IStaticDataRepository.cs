
using AuthCardOpsApi.Core.Dtos;

namespace AuthCardOpsApi.Core.Abstractions
{
  public interface IStaticDataRepository
  {
    public IEnumerable<RoleDto> GetRoles();
  }
}
