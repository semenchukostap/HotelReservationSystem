using HotelReservationSystem.Core.Constants;
using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Infrastructure.Data
{
    public static class DbInitializer
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var context = new ApplicationDbContext(
                serviceProvider.GetRequiredService<DbContextOptions<ApplicationDbContext>>());
            
            // Check if database has been seeded
            if (context.Countries.Any())
                return;
            
            // Seed Countries
            var countries = new List<Country>
            {
                new Country { Name = "USA" },
                new Country { Name = "UK" },
                new Country { Name = "France" },
                new Country { Name = "Italy" },
                new Country { Name = "Spain" },
                new Country { Name = "Germany" },
                new Country { Name = "Japan" }
            };
            
            context.Countries.AddRange(countries);
            await context.SaveChangesAsync();
            
            // Seed Hotels
            var hotels = new List<Hotel>
            {
                new Hotel {
                    Name = "Marriott Resort",
                    City = "New York",
                    CountryId = countries[0].Id,
                    Stars = 5,
                    IsAllInclusive = true,
                    PricePerNight = 299.99m
                },
                new Hotel {
                    Name = "Hilton Garden",
                    City = "London",
                    CountryId = countries[1].Id,
                    Stars = 4,
                    IsAllInclusive = false,
                    PricePerNight = 199.99m
                },
                new Hotel {
                    Name = "Paris Palace",
                    City = "Paris",
                    CountryId = countries[2].Id,
                    Stars = 5,
                    IsAllInclusive = true,
                    PricePerNight = 349.99m
                }
            };
            
            context.Hotels.AddRange(hotels);
            await context.SaveChangesAsync();
            
            // Seed Admin User
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var adminUser = await userManager.FindByEmailAsync("admin@example.com");
            
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = "admin@example.com",
                    Email = "admin@example.com",
                    EmailConfirmed = true,
                    Phone = "1234567890"
                };
                
                await userManager.CreateAsync(adminUser, "Admin@123");
                await userManager.AddToRolesAsync(adminUser, new[] { RoleNames.Administrator, RoleNames.CanManageHotels });
            }
        }
    }
}