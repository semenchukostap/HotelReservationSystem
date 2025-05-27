using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Core.Data
{
    public static class DbInitializer
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            var context = serviceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Ensure database is created and migrated
            context.Database.Migrate();

            // Check if roles exist, create if not
            if (!await roleManager.RoleExistsAsync(RoleName.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));
            }

            if (!await roleManager.RoleExistsAsync(RoleName.User))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.User));
            }

            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }

            // Check if admin user exists, create if not
            if (await userManager.FindByEmailAsync("admin@hotel.com") == null)
            {
                var admin = new ApplicationUser
                {
                    UserName = "admin@hotel.com",
                    Email = "admin@hotel.com",
                    EmailConfirmed = true,
                    Phone = "123456789"
                };

                var result = await userManager.CreateAsync(admin, "Admin123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(admin, RoleName.Admin);
                    await userManager.AddToRoleAsync(admin, RoleName.CanManageHotels);
                }
            }

            // Seed countries if none exist
            if (!context.Countries.Any())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "USA" },
                    new Country { Name = "UK" },
                    new Country { Name = "Spain" },
                    new Country { Name = "France" },
                    new Country { Name = "Germany" }
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}