using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data
{
    public static class DbInitializer
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var services = scope.ServiceProvider;

            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

                // Ensure database is created and migrations are applied
                context.Database.Migrate();

                // Check if roles exist, create them if they don't
                if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
                {
                    await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
                }

                // Seed an admin user if it doesn't exist
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
                    await userManager.CreateAsync(adminUser, "Admin123!");
                    await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
                }

                // Seed other required data (if needed)
                if (!context.Countries.Any())
                {
                    // Add some countries
                    var countries = new List<Country>
                    {
                        new Country { Name = "United States" },
                        new Country { Name = "United Kingdom" },
                        new Country { Name = "France" },
                        new Country { Name = "Germany" },
                        new Country { Name = "Italy" }
                    };
                    context.Countries.AddRange(countries);
                    await context.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                var logger = services.GetRequiredService<ILogger<Program>>();
                logger.LogError(ex, "An error occurred seeding the database.");
            }
        }
    }
}