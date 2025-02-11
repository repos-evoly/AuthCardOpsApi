using AuthApi.Data.Models;

namespace AuthApi.Core.Abstractions
{
  public interface IUnitOfWork : IDisposable
  {
    IRepository<Role> Roles { get; }
    IRepository<User> Users { get; }
    IRepository<Customer> Customers { get; }

    Task SaveAsync();
  }
}