using AuthApi.Data.Models;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System;

namespace AuthApi.Data.Context
{
    public class AuthApiDbContext : DbContext
    {
        public AuthApiDbContext(DbContextOptions<AuthApiDbContext> options) : base(options) { }
        public AuthApiDbContext() { } // ✅ Parameterless constructor for EF Migrations

        // ✅ DbSets for all models
        public DbSet<User> Users => Set<User>();
        public DbSet<Role> Roles => Set<Role>();
        public DbSet<Customer> Customers => Set<Customer>();
        public DbSet<Employee> Employees => Set<Employee>();
        public DbSet<UserSecurity> UserSecurities => Set<UserSecurity>();

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer("Server=DESKTOP-Q6SN24Q,1433;Database=AuthDb;User Id=ccadmin;Password=ccadmin;Trusted_Connection=False;MultipleActiveResultSets=true;TrustServerCertificate=True;");
            }
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // ✅ Unique constraints
            builder.Entity<User>().HasIndex(u => u.Email).IsUnique().HasDatabaseName("Unique_Email");
            builder.Entity<Customer>().HasIndex(c => c.CustomerId).IsUnique().HasDatabaseName("Unique_CustomerId");
            builder.Entity<Employee>().HasIndex(e => e.EmployeeCode).IsUnique().HasDatabaseName("Unique_EmployeeCode");

            // ✅ User → Role (Many-to-One)
            builder.Entity<User>()
                .HasOne(u => u.Role)
                .WithMany(r => r.Users)
                .HasForeignKey(u => u.RoleId)
                .OnDelete(DeleteBehavior.Restrict);

            // ✅ User → UserSecurity (One-to-One) for 2FA
            builder.Entity<User>()
                .HasOne(u => u.UserSecurity)
                .WithOne(us => us.User)
                .HasForeignKey<UserSecurity>(us => us.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // ✅ User → Customer (One-to-One, Nullable)
            builder.Entity<User>()
                .HasOne(u => u.Customer)
                .WithOne(c => c.User)
                .HasForeignKey<Customer>(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // ✅ User → Employee (One-to-One, Nullable)
            builder.Entity<User>()
                .HasOne(u => u.Employee)
                .WithOne(e => e.User)
                .HasForeignKey<Employee>(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // ✅ Unique Constraint on TwoFactorSecretKey
            builder.Entity<UserSecurity>().HasIndex(us => us.TwoFactorSecretKey).IsUnique();
        }

        // ✅ Auto-update CreatedAt and UpdatedAt timestamps
        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            var entries = ChangeTracker.Entries()
                .Where(e => e.Entity is Auditable && (e.State == EntityState.Added || e.State == EntityState.Modified))
                .Select(e => e.Entity as Auditable);

            foreach (var entry in entries)
            {
                if (entry != null)
                {
                    entry.UpdatedAt = DateTime.UtcNow;
                    if (entry.CreatedAt == default)
                    {
                        entry.CreatedAt = DateTime.UtcNow;
                    }
                }
            }

            return base.SaveChangesAsync(cancellationToken);
        }
    }
}
