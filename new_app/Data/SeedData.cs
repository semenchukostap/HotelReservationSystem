using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public static class SeedData
    {
        public static async Task Initialize(ApplicationDbContext context, 
                                           UserManager<ApplicationUser> userManager,
                                           RoleManager<IdentityRole> roleManager)
        {
            await context.Database.MigrateAsync();
            
            // Seed roles
            await SeedRoles(roleManager);
            
            // Seed users
            await SeedUsers(userManager);
            
            // Seed countries
            await SeedCountries(context);
        }
        
        private static async Task SeedRoles(RoleManager<IdentityRole> roleManager)
        {
            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }

            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
            }
        }
        
        private static async Task SeedUsers(UserManager<ApplicationUser> userManager)
        {
            // Create admin user if not exists
            if (await userManager.FindByEmailAsync("admin@example.com") == null)
            {
                var user = new ApplicationUser
                {
                    UserName = "admin@example.com",
                    Email = "admin@example.com",
                    PhoneNumber = "123-456-7890",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(user, "Admin123!");
                
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "Admin");
                    await userManager.AddToRoleAsync(user, RoleName.CanManageHotels);
                }
            }

            // Create regular user if not exists
            if (await userManager.FindByEmailAsync("user@example.com") == null)
            {
                var user = new ApplicationUser
                {
                    UserName = "user@example.com",
                    Email = "user@example.com",
                    PhoneNumber = "987-654-3210",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(user, "User123!");
            }
        }

        private static async Task SeedCountries(ApplicationDbContext context)
        {
            if (!await context.Countries.AnyAsync())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "United States" },
                    new Country { Name = "United Kingdom" },
                    new Country { Name = "Germany" },
                    new Country { Name = "France" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Italy" },
                    new Country { Name = "China" },
                    new Country { Name = "Japan" },
                    new Country { Name = "Australia" },
                    new Country { Name = "Canada" },
                    new Country { Name = "Brazil" },
                    new Country { Name = "India" }
                };

                await context.Countries.AddRangeAsync(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}