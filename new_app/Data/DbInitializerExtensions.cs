using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using new_app.Models;
using System;
using System.Threading.Tasks;

namespace new_app.Data
{
    /// <summary>
    /// Extension methods for database initialization
    /// </summary>
    public static class DbInitializerExtensions
    {
        /// <summary>
        /// Seeds the database asynchronously when the application starts
        /// </summary>
        /// <param name="serviceProvider">The application's service provider</param>
        public static async Task SeedDatabaseAsync(this IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var services = scope.ServiceProvider;

            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

                await DbInitializer.InitializeAsync(context, userManager, roleManager);
            }
            catch (Exception ex)
            {
                // Get the logger and log the error
                var logger = services.GetRequiredService<Microsoft.Extensions.Logging.ILogger<Program>>();
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }
    }
}