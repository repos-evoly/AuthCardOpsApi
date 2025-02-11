using AuthApi.Core.Abstractions;
using AuthApi.Data.Context;
using AuthApi.Data.Models;
using System;
using System.Threading.Tasks;

namespace AuthApi.Core.Repositories
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly AuthApiDbContext _context;

        public IRepository<Role> Roles { get; }
        public IRepository<User> Users { get; }
        public IRepository<Customer> Customers { get; }

        public UnitOfWork(AuthApiDbContext context, IRepository<Role> rolesRepo, IRepository<User> usersRepo, IRepository<Customer> customersRepo)
        {
            _context = context;
            Roles = rolesRepo;
            Users = usersRepo;
            Customers = customersRepo;
        }

        public async Task SaveAsync()
        {
            await _context.SaveChangesAsync();
        }

        public void Dispose()
        {
            _context.Dispose();
        }
    }
}
