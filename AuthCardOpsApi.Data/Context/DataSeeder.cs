using System;
using System.Collections.Generic;
using System.Linq;
using AuthCardOpsApi.Data.Models;
using AuthCardOpsApi.Data.Context;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthCardOpsApi.Data.Seeding
{
    public class DataSeeder
    {
        private readonly AuthCardOpsApiDbContext _context;

        public DataSeeder(AuthCardOpsApiDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public void Seed()
        {
            SeedRoles();
            SeedAdminUser();
            SeedSettings();
        }

        #region Role Seeding
        private void SeedRoles()
        {
            if (!_context.Roles.Any())
            {
                var roles = new List<Role>
                {
                    new() { TitleLT = "SuperAdmin" },
                    new() { TitleLT = "Admin" },
                    new() { TitleLT = "Manager" },
                    new() { TitleLT = "AssistantManager" },
                    new() { TitleLT = "DeputyManager" },
                    new() { TitleLT = "Maker" },
                    new() { TitleLT = "Checker" },
                    new() { TitleLT = "Viewer" },
                    new() { TitleLT = "Auditor" }

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
                    Email = "admin@example.com",
                    Password = BCrypt.Net.BCrypt.HashPassword("Admin@123"), // Hash the password
                    Active = true,
                    RoleId = adminRole,
                    UserSecurity = new UserSecurity()
                };

                _context.Users.Add(adminUser);
                _context.SaveChanges();
            }
        }
        #endregion

        #region Settings Seeding
        private void SeedSettings()
        {
            if (!_context.Settings.Any())
            {
                var settings = new Settings
                {
                    IsTwoFactorAuthEnabled = false,      // Default value; adjust as needed.
                    IsRecaptchaEnabled = false,            // Default value; adjust as needed.
                    RecaptchaSiteKey = "YourRecaptchaSiteKey",   // Replace with your default key if needed.
                    RecaptchaSecretKey = "YourRecaptchaSecretKey", // Replace with your default secret if needed.
                    Url = "http://localhost:5000",         // Default URL.
                    Date = DateTime.UtcNow.ToString("yyyy-MM-dd") // Current UTC date in "yyyy-MM-dd" format.
                };

                _context.Settings.Add(settings);
                _context.SaveChanges();
            }
        }
        #endregion





        #region Public Method to Run Seeder
        public static void Initialize(IServiceProvider serviceProvider)
        {
            using var context = serviceProvider.GetRequiredService<AuthCardOpsApiDbContext>();
            var seeder = new DataSeeder(context);
            seeder.Seed();
        }
        #endregion
    }
}
