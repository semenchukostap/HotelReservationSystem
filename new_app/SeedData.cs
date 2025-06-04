using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using new_app.Data;
using new_app.Models;

namespace new_app;

public static class SeedData
{
    public static async Task Initialize(
        ApplicationDbContext context, 
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager)
    {
        // Ensure the database is created
        await context.Database.EnsureCreatedAsync();
        
        // Seed roles
        await SeedRoles(roleManager);
        
        // Seed admin user
        await SeedAdminUser(userManager);
        
        // Seed countries
        await SeedCountries(context);
    }
    
    private static async Task SeedRoles(RoleManager<IdentityRole> roleManager)
    {
        // Create roles if they don't exist
        if (!await roleManager.RoleExistsAsync(RoleName.Admin))
        {
            await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));
        }
        
        if (!await roleManager.RoleExistsAsync(RoleName.HotelManager))
        {
            await roleManager.CreateAsync(new IdentityRole(RoleName.HotelManager));
        }
    }
    
    private static async Task SeedAdminUser(UserManager<ApplicationUser> userManager)
    {
        // Create admin user if it doesn't exist
        var adminEmail = "admin@example.com";
        var adminUser = await userManager.FindByEmailAsync(adminEmail);
        
        if (adminUser == null)
        {
            adminUser = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true,
                Phone = "123-456-7890"
            };
            
            await userManager.CreateAsync(adminUser, "Admin123!");
            await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
        }
    }
    
    private static async Task SeedCountries(ApplicationDbContext context)
    {
        // Seed countries if they don't exist
        if (!await context.Countries.AnyAsync())
        {
            var countries = new List<Country>
            {
                new Country { Name = "United States" },
                new Country { Name = "United Kingdom" },
                new Country { Name = "France" },
                new Country { Name = "Spain" },
                new Country { Name = "Italy" },
                new Country { Name = "Germany" },
                new Country { Name = "Japan" },
                new Country { Name = "Australia" },
                new Country { Name = "Canada" },
                new Country { Name = "Mexico" }
            };
            
            await context.Countries.AddRangeAsync(countries);
            await context.SaveChangesAsync();
        }
    }
}