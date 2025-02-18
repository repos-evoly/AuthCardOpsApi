using System;
using System.Collections.Generic;
using System.Linq;
using AuthApi.Data.Models;
using AuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthApi.Data.Seeding
{
    public class DataSeeder
    {
        private readonly AuthApiDbContext _context;

        public DataSeeder(AuthApiDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public void Seed()
        {
            SeedRoles();
            SeedAdminUser();
        }

        #region Role Seeding
        private void SeedRoles()
        {
            if (!_context.Roles.Any())
            {
                var roles = new List<Role>
                {
                    new() { TitleLT = "Admin" },
                    new() { TitleLT = "Customer" },
                    new() { TitleLT = "Employee" }
                };

                _context.Roles.AddRange(roles);
                _context.SaveChanges();
            }
        }
        #endregion

        #region Admin User Seeding
        private void SeedAdminUser()
        {
            if (!_context.Users.Any(u => u.Email == "admin@example.com"))
            {
                var adminRole = _context.Roles.FirstOrDefault(r => r.TitleLT == "Admin")?.Id ?? 1;

                var adminUser = new User
                {
                    FullNameAR = "Admin User",
                    FullNameLT = "Admin User",
                    Email = "admin@example.com",
                    Password = BCrypt.Net.BCrypt.HashPassword("Admin@123"), // Hash the password
                    Active = true,
                    RoleId = adminRole
                };

                _context.Users.Add(adminUser);
                _context.SaveChanges();
            }
        }
        #endregion

        

        #region Public Method to Run Seeder
        public static void Initialize(IServiceProvider serviceProvider)
        {
            using var context = serviceProvider.GetRequiredService<AuthApiDbContext>();
            var seeder = new DataSeeder(context);
            seeder.Seed();
        }
        #endregion
    }
}
