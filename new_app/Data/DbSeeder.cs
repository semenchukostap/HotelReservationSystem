using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public static class DbSeeder
    {
        public static async Task SeedRolesAndAdminUser(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            // Ensure database is created
            await context.Database.EnsureCreatedAsync();

            // Add roles if they don't exist
            if (!await roleManager.RoleExistsAsync(RoleName.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));
            }

            // Add admin user if it doesn't exist
            const string adminEmail = "admin@example.com";
            if (await userManager.FindByEmailAsync(adminEmail) == null)
            {
                var adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true,
                    Phone = "123-456-7890"
                };

                var result = await userManager.CreateAsync(adminUser, "Admin123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
                }
            }

            // Seed countries if none exist
            if (!await context.Countries.AnyAsync())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "United States" },
                    new Country { Name = "Canada" },
                    new Country { Name = "United Kingdom" },
                    new Country { Name = "France" },
                    new Country { Name = "Germany" },
                    new Country { Name = "Japan" },
                    new Country { Name = "Australia" },
                    new Country { Name = "Italy" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Mexico" }
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}