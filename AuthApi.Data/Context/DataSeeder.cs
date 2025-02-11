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
            SeedCustomers();
            SeedEmployees();
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

        #region Customer Seeding
        private void SeedCustomers()
        {
            if (!_context.Customers.Any())
            {
                var customerRole = _context.Roles.FirstOrDefault(r => r.TitleLT == "Customer")?.Id ?? 2;

                var user = new User
                {
                    FullNameAR = "John Doe",
                    FullNameLT = "John Doe",
                    Email = "john.doe@example.com",
                    Password = BCrypt.Net.BCrypt.HashPassword("Password123"),
                    Active = true,
                    RoleId = customerRole
                };

                _context.Users.Add(user);
                _context.SaveChanges();

                var customer = new Customer
                {
                    CustomerId = "CUST001",
                    UserId = user.Id,
                    NationalId = "123456789",
                    BirthDate = new DateTime(1990, 5, 15),
                    Address = "123 Main Street",
                    Phone = "+1234567890",
                    KycStatus = "Pending"
                };

                _context.Customers.Add(customer);
                _context.SaveChanges();
            }
        }
        #endregion

        #region Employee Seeding
        private void SeedEmployees()
        {
            if (!_context.Employees.Any())
            {
                var employeeRole = _context.Roles.FirstOrDefault(r => r.TitleLT == "Employee")?.Id ?? 3;

                var user = new User
                {
                    FullNameAR = "Alice Smith",
                    FullNameLT = "Alice Smith",
                    Email = "alice.smith@example.com",
                    Password = BCrypt.Net.BCrypt.HashPassword("Password123"),
                    Active = true,
                    RoleId = employeeRole
                };

                _context.Users.Add(user);
                _context.SaveChanges();

                var employee = new Employee
                {
                    EmployeeCode = "EMP001",
                    UserId = user.Id,
                    Department = "IT",
                    Position = "Software Engineer",
                    Phone = "+1987654321",
                    Email = "alice.smith@example.com",
                    Active = true
                };

                _context.Employees.Add(employee);
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
