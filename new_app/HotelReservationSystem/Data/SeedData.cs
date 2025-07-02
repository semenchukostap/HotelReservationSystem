using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var provider = scope.ServiceProvider;
            
            using var context = new ApplicationDbContext(
                provider.GetRequiredService<DbContextOptions<ApplicationDbContext>>());
            
            var userManager = provider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = provider.GetRequiredService<RoleManager<IdentityRole>>();

            // Ensure admin role exists
            if (!await roleManager.RoleExistsAsync(RoleName.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));
            }

            // Ensure admin user exists
            var adminEmail = "admin@example.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Phone = "123-456-7890",
                    EmailConfirmed = true
                };
                
                await userManager.CreateAsync(adminUser, "Admin@123");
                await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
            }

            // Seed countries if none exist
            if (!context.Countries.Any())
            {
                context.Countries.AddRange(
                    new Country { Name = "United States" },
                    new Country { Name = "Canada" },
                    new Country { Name = "United Kingdom" },
                    new Country { Name = "France" },
                    new Country { Name = "Germany" },
                    new Country { Name = "Italy" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Australia" }
                );
                
                await context.SaveChangesAsync();
            }
        }
    }
}