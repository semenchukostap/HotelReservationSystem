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
            // Ensure database is created
            context.Database.EnsureCreated();

            // Seed roles
            string[] roleNames = { "CanManageHotels" };
            foreach (var roleName in roleNames)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            // Seed admin user
            string adminEmail = "admin@hotel.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                var user = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true,
                    Phone = "123-456-7890"
                };

                var result = await userManager.CreateAsync(user, "Admin123!");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "CanManageHotels");
                }
            }

            // Seed countries
            if (!context.Countries.Any())
            {
                var countries = new List<Country>
                {
                    new Country { Name = "USA" },
                    new Country { Name = "UK" },
                    new Country { Name = "France" },
                    new Country { Name = "Germany" },
                    new Country { Name = "Italy" },
                    new Country { Name = "Spain" }
                };

                context.Countries.AddRange(countries);
                await context.SaveChangesAsync();
            }
        }
    }
}