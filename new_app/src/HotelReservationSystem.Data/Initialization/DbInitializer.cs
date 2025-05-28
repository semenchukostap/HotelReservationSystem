using HotelReservationSystem.Core.Constants;
using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Data.Initialization;

public static class DbInitializer
{
    public static async Task InitializeAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var services = scope.ServiceProvider;
        
        var context = services.GetRequiredService<ApplicationDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        
        // Ensure database is created
        await context.Database.EnsureCreatedAsync();
        
        // Seed roles
        if (!await roleManager.RoleExistsAsync(RoleNames.Administrator))
        {
            await roleManager.CreateAsync(new IdentityRole(RoleNames.Administrator));
        }
        
        if (!await roleManager.RoleExistsAsync(RoleNames.CanManageHotels))
        {
            await roleManager.CreateAsync(new IdentityRole(RoleNames.CanManageHotels));
        }
        
        // Seed admin user
        if (!context.Users.Any())
        {
            var adminUser = new ApplicationUser
            {
                UserName = "admin@hotelreservation.com",
                Email = "admin@hotelreservation.com",
                Phone = "123-456-7890",
                EmailConfirmed = true
            };
            
            var result = await userManager.CreateAsync(adminUser, "Admin@123");
            if (result.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, RoleNames.Administrator);
                await userManager.AddToRoleAsync(adminUser, RoleNames.CanManageHotels);
            }
        }
        
        // Seed countries
        if (!context.Countries.Any())
        {
            var countries = new[]
            {
                new Country { Name = "USA" },
                new Country { Name = "UK" },
                new Country { Name = "Germany" },
                new Country { Name = "France" },
                new Country { Name = "Spain" }
            };
            
            await context.Countries.AddRangeAsync(countries);
            await context.SaveChangesAsync();
        }
    }
}