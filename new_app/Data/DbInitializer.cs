using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Data
{
    public static class DbInitializer
    {
        public static async Task Initialize(IServiceProvider serviceProvider, IWebHostEnvironment env)
        {
            var context = serviceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Create roles if they don't exist
            if (!await roleManager.RoleExistsAsync(RoleName.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));
            }

            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }

            // Check if admin user exists, if not create it
            var adminEmail = "admin@example.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Phone = "123456789"
                };

                var result = await userManager.CreateAsync(adminUser, "Admin123!");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
                    await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
                }
            }

            // Seed countries if none exist
            if (!context.Countries.Any())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "United States" },
                    new Country { Name = "United Kingdom" },
                    new Country { Name = "Germany" },
                    new Country { Name = "France" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Italy" },
                    new Country { Name = "Japan" },
                    new Country { Name = "China" }
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}