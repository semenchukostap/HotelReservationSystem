using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data;

/// <summary>
/// Provides data seeding functionality for the application
/// </summary>
public static class SeedData
{
    /// <summary>
    /// Initializes the database with seed data
    /// </summary>
    /// <param name="serviceProvider">The service provider for dependency injection</param>
    public static async Task Initialize(IServiceProvider serviceProvider)
    {
        using var context = new ApplicationDbContext(
            serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>());
        
        // Make sure we have the database created
        await context.Database.MigrateAsync();
        
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        
        // Ensure roles exist
        await EnsureRoles(roleManager);
        
        // Seed countries if needed
        await SeedCountries(context);
        
        // Seed admin user if needed
        await SeedAdminUser(userManager);
    }
    
    /// <summary>
    /// Ensures that required application roles exist
    /// </summary>
    private static async Task EnsureRoles(RoleManager<IdentityRole> roleManager)
    {
        // Check if the CanManageHotels role exists, and create it if it doesn't
        if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
        {
            await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
        }

        // Add any additional roles as needed
    }
    
    /// <summary>
    /// Seeds the Countries table with initial data if it's empty
    /// </summary>
    private static async Task SeedCountries(ApplicationDbContext context)
    {
        // Only seed if the table is empty
        if (await context.Countries.AnyAsync())
            return; 
        
        // Add countries from the original migration
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
            new Country { Name = "Portugal" }, // Fixed typo from original "Portual"
            new Country { Name = "England" },
            new Country { Name = "United Kingdom" },
            new Country { Name = "USA" }
        };
        
        await context.Countries.AddRangeAsync(countries);
        await context.SaveChangesAsync();
    }
    
    /// <summary>
    /// Seeds an admin user with the CanManageHotels role if it doesn't exist
    /// </summary>
    private static async Task SeedAdminUser(UserManager<ApplicationUser> userManager)
    {
        // Admin user credentials - in a production environment, these should be retrieved 
        // from a secure configuration source like Azure Key Vault or user secrets
        const string adminEmail = "admin@admin.com";
        const string adminPassword = "Admin123!"; // Should be generated or stored securely
        
        // Check if the admin already exists
        if (await userManager.FindByEmailAsync(adminEmail) != null)
            return; 
        
        // Create the admin user
        var user = new ApplicationUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            Phone = "1234567890",
            EmailConfirmed = true, // Pre-confirm the email for convenience
            PhoneNumberConfirmed = false,
            TwoFactorEnabled = false,
            LockoutEnabled = true
        };
        
        // Add the user and assign the role
        var result = await userManager.CreateAsync(user, adminPassword);
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(user, RoleName.CanManageHotels);
        }
        else
        {
            var exceptions = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new ApplicationException($"Cannot create admin user. Errors: {exceptions}");
        }
    }
    
    /// <summary>
    /// Extension helper method for GetRequiredService to make it available to this static class
    /// </summary>
    private static T GetRequiredService<T>(this IServiceProvider provider) where T : notnull
    {
        return (T)provider.GetService(typeof(T))!;
    }
}