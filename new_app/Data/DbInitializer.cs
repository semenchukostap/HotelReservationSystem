using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using new_app.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace new_app.Data
{
    /// <summary>
    /// Database initializer for seeding initial data in the application
    /// </summary>
    public static class DbInitializer
    {
        /// <summary>
        /// Initialize the database with seed data
        /// </summary>
        /// <param name="context">The application database context</param>
        /// <param name="userManager">The user manager for creating users</param>
        /// <param name="roleManager">The role manager for creating roles</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public static async Task InitializeAsync(ApplicationDbContext context, 
            UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager)
        {
            // Ensure database is created and apply pending migrations
            context.Database.Migrate();

            // Seed countries if none exist
            await SeedCountriesAsync(context);

            // Seed roles if none exist
            await SeedRolesAsync(roleManager);

            // Seed users if none exist
            await SeedUsersAsync(userManager);
        }

        /// <summary>
        /// Seed countries if they don't exist
        /// </summary>
        /// <param name="context">The application database context</param>
        private static async Task SeedCountriesAsync(ApplicationDbContext context)
        {
            // Check if countries already exist
            if (context.Countries.Any())
            {
                return; // Countries already seeded
            }

            // Countries to seed based on existing migration data
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
                new Country { Name = "Portugal" }, // Corrected spelling from "Portual" in original data
                new Country { Name = "England" }
            };

            // Add countries to context
            await context.Countries.AddRangeAsync(countries);
            await context.SaveChangesAsync();
        }

        /// <summary>
        /// Seed roles if they don't exist
        /// </summary>
        /// <param name="roleManager">The role manager for creating roles</param>
        private static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            // Check and create the CanManageHotels role if it doesn't exist
            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }
        }

        /// <summary>
        /// Seed users if they don't exist
        /// </summary>
        /// <param name="userManager">The user manager for creating users</param>
        private static async Task SeedUsersAsync(UserManager<ApplicationUser> userManager)
        {
            // Create admin users
            await CreateUserIfNotExistsAsync(userManager, "admin@book.go", "Admin@123", RoleName.CanManageHotels);
            await CreateUserIfNotExistsAsync(userManager, "admin@admin.com", "Admin@123", RoleName.CanManageHotels);
            
            // Create a regular guest user
            await CreateUserIfNotExistsAsync(userManager, "guest@book.go", "Guest@123");
        }

        /// <summary>
        /// Create a user if one with the specified email doesn't exist
        /// </summary>
        /// <param name="userManager">The user manager for creating users</param>
        /// <param name="email">The email address of the user</param>
        /// <param name="password">The password for the user</param>
        /// <param name="role">Optional role to assign to the user</param>
        private static async Task CreateUserIfNotExistsAsync(
            UserManager<ApplicationUser> userManager, 
            string email, 
            string password, 
            string role = null)
        {
            var user = await userManager.FindByEmailAsync(email);
            
            // Check if user exists
            if (user == null)
            {
                // Create a new user
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    Phone = "000-000-0000" // Default phone number as it's required
                };

                var result = await userManager.CreateAsync(user, password);
                
                if (result.Succeeded && !string.IsNullOrEmpty(role))
                {
                    // Assign role to the user if specified
                    await userManager.AddToRoleAsync(user, role);
                }
            }
        }
    }
}