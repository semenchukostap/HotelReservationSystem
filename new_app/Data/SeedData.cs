using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Data
{
    public static class SeedData
    {
        public static async Task Initialize(ApplicationDbContext context, 
            UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager)
        {
            // Seed Roles
            await SeedRoles(roleManager);
            
            // Seed Admin User
            await SeedAdminUser(userManager);
            
            // Seed Countries
            await SeedCountries(context);
        }

        private static async Task SeedRoles(RoleManager<IdentityRole> roleManager)
        {
            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }
        }

        private static async Task SeedAdminUser(UserManager<ApplicationUser> userManager)
        {
            const string adminEmail = "admin@hotel.com";
            const string adminPassword = "Admin123!";

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

                var result = await userManager.CreateAsync(adminUser, adminPassword);
                
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
                }
            }
        }

        private static async Task SeedCountries(ApplicationDbContext context)
        {
            if (!context.Countries.Any())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "Bulgaria" },
                    new Country { Name = "United States" },
                    new Country { Name = "Germany" },
                    new Country { Name = "United Kingdom" },
                    new Country { Name = "France" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Italy" },
                    new Country { Name = "Greece" },
                    new Country { Name = "Turkey" }
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}