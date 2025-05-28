using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Data.Configuration
{
    public static class DatabaseInitializer
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var services = scope.ServiceProvider;
            
            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
                
                // Ensure database is created
                context.Database.EnsureCreated();
                
                // Apply any pending migrations
                if (context.Database.GetPendingMigrations().Any())
                {
                    context.Database.Migrate();
                }
                
                // Seed initial data
                await SeedData(context, userManager, roleManager);
            }
            catch (Exception ex)
            {
                // Log any error during initialization
                var logger = services.GetRequiredService<ILogger<ApplicationDbContext>>();
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }
        
        private static async Task SeedData(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            // Seed Countries if empty
            if (!context.Countries.Any())
            {
                context.Countries.AddRange(
                    new Country { Name = "Egypt" },
                    new Country { Name = "Poland" },
                    new Country { Name = "Germany" },
                    new Country { Name = "Spain" },
                    new Country { Name = "Greece" },
                    new Country { Name = "Turkey" },
                    new Country { Name = "Malta" },
                    new Country { Name = "France" },
                    new Country { Name = "Portugal" },
                    new Country { Name = "England" }
                );
                
                await context.SaveChangesAsync();
            }
            
            // Seed Roles
            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }
            
            // Seed Admin user
            var adminEmail = "admin@bookandgo.com";
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
                
                var password = "Admin@123456";
                var result = await userManager.CreateAsync(adminUser, password);
                
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
                }
            }
        }
    }
}