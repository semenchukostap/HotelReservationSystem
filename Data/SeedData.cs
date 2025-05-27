using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data
{
    public static class SeedData
    {
        public static async Task Initialize(ApplicationDbContext context, 
            UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager)
        {
            // Ensure the database is created
            context.Database.EnsureCreated();

            // Check if there are any users in the database
            if (!userManager.Users.Any())
            {
                // Create roles if they don't exist
                if (!await roleManager.RoleExistsAsync(RoleName.Admin))
                    await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));

                if (!await roleManager.RoleExistsAsync(RoleName.User))
                    await roleManager.CreateAsync(new IdentityRole(RoleName.User));

                // Create admin user
                var adminUser = new ApplicationUser
                {
                    UserName = "admin@domain.com",
                    Email = "admin@domain.com",
                    EmailConfirmed = true,
                    Phone = "123-456-7890"
                };

                var result = await userManager.CreateAsync(adminUser, "Admin@123");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
                }

                // Create regular user
                var regularUser = new ApplicationUser
                {
                    UserName = "user@domain.com",
                    Email = "user@domain.com",
                    EmailConfirmed = true,
                    Phone = "123-456-7890"
                };

                result = await userManager.CreateAsync(regularUser, "User@123");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(regularUser, RoleName.User);
                }
            }

            // Seed countries if needed
            if (!context.Countries.Any())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "USA" },
                    new Country { Name = "UK" },
                    new Country { Name = "Germany" },
                    new Country { Name = "France" },
                    new Country { Name = "Spain" }
                };

                await context.Countries.AddRangeAsync(countries);
                await context.SaveChangesAsync();
            }

            // Additional seed data can be added as needed based on the original migrations
        }
    }
}