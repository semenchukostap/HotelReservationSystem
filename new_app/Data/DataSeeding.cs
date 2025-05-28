using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data;

public static class DataSeeding
{
    public static async Task SeedRolesAndUsersAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        // Seed Roles
        await SeedRolesAsync(roleManager);

        // Seed Admin User
        await SeedAdminUserAsync(userManager);
    }

    private static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
    {
        if (!await roleManager.RoleExistsAsync(RoleName.Admin))
            await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));

        if (!await roleManager.RoleExistsAsync(RoleName.User))
            await roleManager.CreateAsync(new IdentityRole(RoleName.User));
    }

    private static async Task SeedAdminUserAsync(UserManager<ApplicationUser> userManager)
    {
        // Check if admin user exists and create if not
        if (await userManager.FindByEmailAsync("admin@example.com") == null)
        {
            var adminUser = new ApplicationUser
            {
                UserName = "admin@example.com",
                Email = "admin@example.com",
                Phone = "123456789",
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(adminUser, "Admin123!");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
            }
        }
    }

    public static async Task SeedCountriesAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        if (!await context.Countries.AnyAsync())
        {
            var countries = new List<Country>
            {
                new Country { Name = "United States" },
                new Country { Name = "United Kingdom" },
                new Country { Name = "France" },
                new Country { Name = "Germany" },
                new Country { Name = "Spain" },
                new Country { Name = "Italy" },
                new Country { Name = "Japan" },
                new Country { Name = "Australia" }
            };

            context.Countries.AddRange(countries);
            await context.SaveChangesAsync();
        }
    }
}