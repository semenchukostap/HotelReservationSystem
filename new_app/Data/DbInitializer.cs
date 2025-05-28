using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using HotelReservationSystem.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Data
{
    /// <summary>
    /// Database initialization service that sets up initial data, roles, admin user, and seed data.
    /// Used instead of Entity Framework migrations for initial setup.
    /// </summary>
    public static class DbInitializer
    {
        public static async Task Initialize(IServiceProvider serviceProvider, IWebHostEnvironment env)
        {
            var context = serviceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();

            context.Database.EnsureCreated();

            // Check if roles exist
            if (!await roleManager.RoleExistsAsync(RoleName.Admin))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));
            }

            if (!await roleManager.RoleExistsAsync(RoleName.CanManageHotels))
            {
                await roleManager.CreateAsync(new IdentityRole(RoleName.CanManageHotels));
            }

            // Check if admin user exists
            var adminEmail = "admin@admin.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Phone = "123456789"
                };

                var result = await userManager.CreateAsync(adminUser, "Admin123!");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
                    await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
                }
            }

            // Seed countries if none exist
            if (!context.Countries.Any())
            {
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
                    new Country { Name = "Portugal" }, // Fixed typo from "Portual" in original data
                    new Country { Name = "England" },
                    new Country { Name = "United States" },
                    new Country { Name = "Japan" },
                    new Country { Name = "China" },
                    new Country { Name = "Italy" }
                };

                await context.Countries.AddRangeAsync(countries);
                await context.SaveChangesAsync();
            }
            
            // Create a demo customer if none exist
            if (!context.Customers.Any())
            {
                var demoCustomer = new Customer
                {
                    Name = "Demo Customer",
                    Birthdate = new DateTime(1990, 1, 1)
                };
                
                await context.Customers.AddAsync(demoCustomer);
                await context.SaveChangesAsync();
            }
            
            // Create a demo hotel if none exist
            if (!context.Hotels.Any())
            {
                var country = await context.Countries.FirstOrDefaultAsync();
                if (country != null)
                {
                    var demoHotel = new Hotel
                    {
                        Name = "Demo Hotel",
                        CountryId = country.Id,
                        City = "Demo City",
                        Stars = 4,
                        PricePerNight = 150.00,
                        IsAllInclusive = true
                    };
                    
                    await context.Hotels.AddAsync(demoHotel);
                    await context.SaveChangesAsync();
                }
            }
        }
    }
}