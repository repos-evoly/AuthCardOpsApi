using AutoMapper;
using AuthCardOpsApi.Core.Dtos;
using AuthCardOpsApi.Data.Context;
using AuthCardOpsApi.Core.Abstractions;

namespace AuthCardOpsApi.Core.Repositories
{
  public class StaticDataRepository : IStaticDataRepository
  {
    private readonly AuthCardOpsApiDbContext _db;
    private readonly IMapper _mapper;

    public StaticDataRepository(AuthCardOpsApiDbContext db, IMapper mapper)
    {
      _db = db;
      _mapper = mapper;
    }

    public IEnumerable<RoleDto> GetRoles()
    {
      return _mapper.Map<IEnumerable<RoleDto>>(_db.Roles.ToList());
    }

  }
}