using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Data
{
    public static class DbInitializer
    {
        public static async Task InitializeAsync(
            ApplicationDbContext context, 
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            context.Database.EnsureCreated();
            
            // Create roles if they don't exist
            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }
            
            // Create admin user if it doesn't exist
            var adminEmail = "admin@example.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Phone = "1234567890",
                    EmailConfirmed = true
                };
                
                await userManager.CreateAsync(adminUser, "Admin123!");
                await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
            }
            
            // Seed countries if needed
            if (!context.Countries.Any())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "Bulgaria" },
                    new Country { Name = "Greece" },
                    new Country { Name = "Turkey" },
                    new Country { Name = "Spain" }
                };
                
                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}