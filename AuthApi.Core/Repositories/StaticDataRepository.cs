using AutoMapper;
using AuthApi.Core.Dtos;
using AuthApi.Data.Context;
using AuthApi.Core.Abstractions;

namespace AuthApi.Core.Repositories
{
  public class StaticDataRepository : IStaticDataRepository
  {
    private readonly AuthApiDbContext _db;
    private readonly IMapper _mapper;

    public StaticDataRepository(AuthApiDbContext db, IMapper mapper)
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