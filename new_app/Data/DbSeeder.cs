using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    /// <summary>
    /// Static class to handle database seeding operations
    /// </summary>
    public static class DbSeeder
    {
        /// <summary>
        /// Seeds roles, admin user, and initial data to the database
        /// </summary>
        /// <param name="serviceProvider">The application's service provider</param>
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
            const string adminEmail = "admin@admin.com";
            if (await userManager.FindByEmailAsync(adminEmail) == null)
            {
                var adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true,
                    Phone = "123-456-7890"
                };

                var result = await userManager.CreateAsync(adminUser, "Admin1!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
                }
            }

            await SeedCountries(context);
        }

        /// <summary>
        /// Seeds the countries data if no countries exist
        /// </summary>
        /// <param name="context">The application database context</param>
        private static async Task SeedCountries(ApplicationDbContext context)
        {
            // Seed countries if none exist
            if (!await context.Countries.AnyAsync())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "Egypt" },
                    new Country { Name = "Poland" },
                    new Country { Name = "Germany" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Greece" },
                    new Country { Name = "Turkey" },
                    new Country { Name = "Malta" },
                    new Country { Name = "France" },
                    new Country { Name = "Portugal" }, // Corrected from "Portual" in original
                    new Country { Name = "England" }
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}