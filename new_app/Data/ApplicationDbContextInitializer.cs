using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public static class ApplicationDbContextInitializer
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider, IWebHostEnvironment environment)
        {
            using var scope = serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Ensure database is created
            context.Database.EnsureCreated();

            // Seed roles if needed
            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }

            // Add initial countries if needed
            if (!context.Countries.Any())
            {
                context.Countries.AddRange(
                    new Country { Name = "USA" },
                    new Country { Name = "UK" },
                    new Country { Name = "France" },
                    new Country { Name = "Germany" },
                    new Country { Name = "Japan" },
                    new Country { Name = "Australia" }
                );

                await context.SaveChangesAsync();
            }

            // Add admin user if needed
            var adminUser = await userManager.FindByEmailAsync("admin@example.com");
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = "admin@example.com",
                    Email = "admin@example.com",
                    EmailConfirmed = true,
                    Phone = "1234567890"
                };

                await userManager.CreateAsync(adminUser, "Admin@123"); // Replace with secure password
                await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
            }
        }
    }
}