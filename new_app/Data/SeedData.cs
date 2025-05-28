using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Data;

/// <summary>
/// Provides data seeding functionality for the application.
/// This class replaces the traditional Migrations/Configuration.cs approach and SQL-based seed migrations
/// that were used in older versions of Entity Framework. It allows for programmatic seeding of
/// initial data when the application starts, ensuring consistent database state across environments.
/// </summary>
public static class SeedData
{
    /// <summary>
    /// Initializes the database with seed data.
    /// This method is called during application startup to ensure that the database
    /// contains all required initial data. It handles database migration, role creation,
    /// country data, and admin user setup in a single unified process.
    /// </summary>
    /// <param name="serviceProvider">The service provider for dependency injection, which provides access to required services</param>
    /// <returns>A task representing the asynchronous operation</returns>
    public static async Task Initialize(IServiceProvider serviceProvider)
    {
        using var context = new ApplicationDbContext(
            serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>());
        
        // Make sure we have the database created and all migrations applied
        // This replaces the old MigrateDatabaseToLatestVersion initializer from EF6
        await context.Database.MigrateAsync();
        
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        
        // Ensure roles exist - replacing separate SQL role creation scripts
        await EnsureRoles(roleManager);
        
        // Seed countries if needed - replacing INSERT statements in SQL migration files
        await SeedCountries(context);
        
        // Seed admin user if needed - replacing manual user creation or SQL-based user seeding
        await SeedAdminUser(userManager);
    }
    
    /// <summary>
    /// Ensures that required application roles exist in the database.
    /// This method checks for the existence of predefined roles and creates them if they don't exist,
    /// replacing the need for separate SQL scripts to insert roles.
    /// </summary>
    /// <param name="roleManager">The role manager service for role operations</param>
    /// <returns>A task representing the asynchronous operation</returns>
    private static async Task EnsureRoles(RoleManager<IdentityRole> roleManager)
    {
        // Check if the CanManageHotels role exists, and create it if it doesn't
        // This replaces INSERT statements in SQL migrations for role creation
        if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
        {
            await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
        }

        // Add any additional roles as needed
    }
    
    /// <summary>
    /// Seeds the Countries table with initial data if it's empty.
    /// This method provides a code-first approach to populating reference data,
    /// replacing the SQL INSERT statements that would typically be found in migration scripts.
    /// The countries list is critical for the hotel management functionality.
    /// </summary>
    /// <param name="context">The application database context</param>
    /// <returns>A task representing the asynchronous operation</returns>
    private static async Task SeedCountries(ApplicationDbContext context)
    {
        // Only seed if the table is empty - this prevents duplicate entries
        // when the application restarts and ensures idempotence
        if (await context.Countries.AnyAsync())
            return; 
        
        // Add countries from the original migration
        // This replaces SQL INSERT statements in the original migrations
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
    /// Seeds an admin user with the CanManageHotels role if it doesn't exist.
    /// This method programmatically creates the initial administrator account,
    /// replacing the need for manual setup or SQL scripts to insert user data.
    /// Having a default admin account ensures that there is always a user with
    /// full system access, particularly important for initial setup.
    /// </summary>
    /// <param name="userManager">The user manager service for user operations</param>
    /// <returns>A task representing the asynchronous operation</returns>
    private static async Task SeedAdminUser(UserManager<ApplicationUser> userManager)
    {
        // Admin user credentials - in a production environment, these should be retrieved 
        // from a secure configuration source like Azure Key Vault or user secrets
        const string adminEmail = "admin@admin.com";
        const string adminPassword = "Admin123!"; // Should be generated or stored securely
        
        // Check if the admin already exists to ensure idempotence
        if (await userManager.FindByEmailAsync(adminEmail) != null)
            return; 
        
        // Create the admin user with Identity Framework instead of direct SQL inserts
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
        
        // Add the user and assign the role programmatically
        // This replaces both user creation SQL and role assignment SQL
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
    /// Extension helper method for GetRequiredService to make it available to this static class.
    /// This method simplifies service resolution within the seed data implementation,
    /// allowing for cleaner code when working with the dependency injection container.
    /// </summary>
    /// <typeparam name="T">The type of service to retrieve</typeparam>
    /// <param name="provider">The service provider instance</param>
    /// <returns>The requested service instance</returns>
    private static T GetRequiredService<T>(this IServiceProvider provider) where T : notnull
    {
        return (T)provider.GetService(typeof(T))!;
    }
}