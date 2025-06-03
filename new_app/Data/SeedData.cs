using Microsoft.AspNetCore.Identity;
using new_app.Models;

namespace new_app.Data
{
    public static class SeedData
    {
        public static async Task Initialize(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            context.Database.EnsureCreated();

            // Add countries if they don't exist
            if (!context.Countries.Any())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "USA" },
                    new Country { Name = "UK" },
                    new Country { Name = "Germany" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Greece" },
                    new Country { Name = "France" },
                    new Country { Name = "Poland" },
                    new Country { Name = "Turkey" },
                    new Country { Name = "Malta" },
                    new Country { Name = "Portugal" },
                    new Country { Name = "Egypt" },
                    // Add more countries as needed
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }

            // Create roles if they don't exist
            string[] roleNames = { "CanManageHotels" };
            foreach (var roleName in roleNames)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            // Create admin user if it doesn't exist
            var adminEmail = "admin@hotel.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                var user = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Phone = "123-456-7890"
                };

                var result = await userManager.CreateAsync(user, "Admin123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "CanManageHotels");
                }
            }
        }
    }
}