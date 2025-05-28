using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public static class DbInitializer
    {
        public static async Task Initialize(ApplicationDbContext context, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            // Create database if it doesn't exist
            context.Database.EnsureCreated();

            // Look for any countries
            if (!context.Countries.Any())
            {
                // Seed countries
                var countries = new List<Country>
                {
                    new Country { Name = "Bulgaria" },
                    new Country { Name = "Greece" },
                    new Country { Name = "Turkey" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Italy" },
                    new Country { Name = "Egypt" }
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }

            // Check if the admin role exists
            if (!await roleManager.RoleExistsAsync(RoleConstants.Admin))
            {
                // Create admin role
                await roleManager.CreateAsync(new IdentityRole(RoleConstants.Admin));
                await roleManager.CreateAsync(new IdentityRole(RoleConstants.CanManageHotels));
            }

            // Check if admin user exists
            var adminUser = await userManager.FindByEmailAsync("admin@bookandgo.com");
            if (adminUser == null)
            {
                // Create admin user
                adminUser = new ApplicationUser
                {
                    UserName = "admin@bookandgo.com",
                    Email = "admin@bookandgo.com",
                    EmailConfirmed = true,
                    Phone = "1234567890"
                };

                var result = await userManager.CreateAsync(adminUser, "Admin123!");
                if (result.Succeeded)
                {
                    // Assign admin role
                    await userManager.AddToRoleAsync(adminUser, RoleConstants.Admin);
                    await userManager.AddToRoleAsync(adminUser, RoleConstants.CanManageHotels);
                }
            }
        }
    }
}