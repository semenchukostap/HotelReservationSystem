using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace HotelReservationSystem.Data
{
    public class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var context = new ApplicationDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>());

            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            // Ensure the database is created
            await context.Database.EnsureCreatedAsync();

            // Seed Countries
            if (!await context.Countries.AnyAsync())
            {
                await context.Countries.AddRangeAsync(
                    new Country { Name = "Bulgaria" },
                    new Country { Name = "Greece" },
                    new Country { Name = "Italy" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Turkey" }
                );

                await context.SaveChangesAsync();
            }

            // Seed Roles
            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }

            // Seed Admin User
            const string adminEmail = "admin@hotel.com";
            var admin = await userManager.FindByEmailAsync(adminEmail);

            if (admin == null)
            {
                admin = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Phone = "123-456-7890",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(admin, "Admin123!");
                
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(admin, RoleName.CanManageHotels);
                }
            }
        }
    }
}