using AuthCardOpsApi.Data.Models;

namespace AuthCardOpsApi.Core.Abstractions
{
  public interface IUnitOfWork : IDisposable
  {
    IRepository<Role> Roles { get; }
    IRepository<User> Users { get; }
    IRepository<Settings> Settings { get; }

    Task SaveAsync();
  }
}