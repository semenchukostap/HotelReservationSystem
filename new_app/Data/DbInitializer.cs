using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using HotelReservationSystem.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HotelReservationSystem.Data
{
    /// <summary>
    /// Database initialization service that sets up initial data, roles, users, and seed data.
    /// Used for initial setup and providing demo data in development environments.
    /// </summary>
    public static class DbInitializer
    {
        /// <summary>
        /// Initializes the database with roles, users, and seed data.
        /// </summary>
        /// <param name="serviceProvider">The application's service provider for dependency resolution</param>
        /// <param name="env">The web hosting environment to determine if running in development</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public static async Task Initialize(IServiceProvider serviceProvider, IWebHostEnvironment env)
        {
            using var scope = serviceProvider.CreateScope();
            var services = scope.ServiceProvider;
            var logger = services.GetRequiredService<ILogger<ApplicationDbContext>>();

            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

                // Ensure database is created
                await context.Database.EnsureCreatedAsync();

                // Initialize roles
                await InitializeRolesAsync(roleManager, logger);

                // Initialize users
                await InitializeUsersAsync(userManager, logger);

                // Seed data
                await SeedDataAsync(context, env, logger);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while initializing the database.");
                throw;
            }
        }

        /// <summary>
        /// Initializes application roles if they don't exist.
        /// </summary>
        /// <param name="roleManager">The role manager service</param>
        /// <param name="logger">The logger instance</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private static async Task InitializeRolesAsync(RoleManager<IdentityRole> roleManager, ILogger logger)
        {
            logger.LogInformation("Initializing roles");

            string[] roleNames = { RoleName.Admin, RoleName.CanManageHotels };
            
            foreach (var roleName in roleNames)
            {
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    logger.LogInformation("Creating role {RoleName}", roleName);
                    await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }
        }

        /// <summary>
        /// Initializes admin user if they don't exist.
        /// </summary>
        /// <param name="userManager">The user manager service</param>
        /// <param name="logger">The logger instance</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private static async Task InitializeUsersAsync(UserManager<ApplicationUser> userManager, ILogger logger)
        {
            logger.LogInformation("Initializing users");

            // Setup admin user
            var adminEmail = "admin@admin.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);

            if (adminUser == null)
            {
                logger.LogInformation("Creating admin user");
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    Phone = "123456789",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(adminUser, "Admin123!");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, RoleName.Admin);
                    await userManager.AddToRoleAsync(adminUser, RoleName.CanManageHotels);
                    logger.LogInformation("Admin user created successfully");
                }
                else
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    logger.LogError("Failed to create admin user: {Errors}", errors);
                }
            }

            // Setup regular user
            var regularUserEmail = "user@example.com";
            var regularUser = await userManager.FindByEmailAsync(regularUserEmail);

            if (regularUser == null)
            {
                logger.LogInformation("Creating regular user");
                regularUser = new ApplicationUser
                {
                    UserName = regularUserEmail,
                    Email = regularUserEmail,
                    Phone = "987654321",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(regularUser, "User123!");

                if (result.Succeeded)
                {
                    logger.LogInformation("Regular user created successfully");
                }
                else
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    logger.LogError("Failed to create regular user: {Errors}", errors);
                }
            }
        }

        /// <summary>
        /// Seeds the database with countries, hotels, customers, and orders.
        /// </summary>
        /// <param name="context">The application database context</param>
        /// <param name="env">The web hosting environment to determine if running in development</param>
        /// <param name="logger">The logger instance</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private static async Task SeedDataAsync(ApplicationDbContext context, IWebHostEnvironment env, ILogger logger)
        {
            logger.LogInformation("Seeding database data");

            // Seed countries
            await SeedCountriesAsync(context, logger);

            // Only seed demo data in development environment
            if (env.IsDevelopment())
            {
                await SeedCustomersAsync(context, logger);
                await SeedHotelsAsync(context, logger);
                await SeedOrdersAsync(context, logger);
            }
        }

        /// <summary>
        /// Seeds the database with countries if none exist.
        /// </summary>
        /// <param name="context">The application database context</param>
        /// <param name="logger">The logger instance</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private static async Task SeedCountriesAsync(ApplicationDbContext context, ILogger logger)
        {
            if (!await context.Countries.AnyAsync())
            {
                logger.LogInformation("Seeding countries");

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
                logger.LogInformation("Countries seeded successfully");
            }
        }

        /// <summary>
        /// Seeds the database with customers if none exist.
        /// </summary>
        /// <param name="context">The application database context</param>
        /// <param name="logger">The logger instance</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private static async Task SeedCustomersAsync(ApplicationDbContext context, ILogger logger)
        {
            if (!await context.Customers.AnyAsync())
            {
                logger.LogInformation("Seeding customers");

                var customers = new List<Customer>
                {
                    new Customer
                    {
                        Name = "Demo Customer",
                        Birthdate = new DateTime(1990, 1, 1)
                    },
                    new Customer
                    {
                        Name = "John Doe",
                        Birthdate = new DateTime(1985, 5, 15)
                    },
                    new Customer
                    {
                        Name = "Jane Smith",
                        Birthdate = new DateTime(1992, 8, 22)
                    }
                };

                await context.Customers.AddRangeAsync(customers);
                await context.SaveChangesAsync();
                logger.LogInformation("Customers seeded successfully");
            }
        }

        /// <summary>
        /// Seeds the database with hotels if none exist.
        /// </summary>
        /// <param name="context">The application database context</param>
        /// <param name="logger">The logger instance</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private static async Task SeedHotelsAsync(ApplicationDbContext context, ILogger logger)
        {
            if (!await context.Hotels.AnyAsync())
            {
                logger.LogInformation("Seeding hotels");

                var countries = await context.Countries.ToListAsync();
                
                if (countries.Any())
                {
                    var hotels = new List<Hotel>
                    {
                        new Hotel
                        {
                            Name = "Demo Hotel",
                            CountryId = countries.First(c => c.Name == "Egypt").Id,
                            City = "Cairo",
                            Stars = 4,
                            PricePerNight = 150.00,
                            IsAllInclusive = true
                        },
                        new Hotel
                        {
                            Name = "Luxury Resort",
                            CountryId = countries.First(c => c.Name == "Greece").Id,
                            City = "Santorini",
                            Stars = 5,
                            PricePerNight = 350.00,
                            IsAllInclusive = true
                        },
                        new Hotel
                        {
                            Name = "Budget Stay",
                            CountryId = countries.First(c => c.Name == "Poland").Id,
                            City = "Warsaw",
                            Stars = 3,
                            PricePerNight = 85.00,
                            IsAllInclusive = false
                        }
                    };

                    await context.Hotels.AddRangeAsync(hotels);
                    await context.SaveChangesAsync();
                    logger.LogInformation("Hotels seeded successfully");
                }
                else
                {
                    logger.LogWarning("No countries found to associate with hotels");
                }
            }
        }

        /// <summary>
        /// Seeds the database with orders if none exist.
        /// </summary>
        /// <param name="context">The application database context</param>
        /// <param name="logger">The logger instance</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private static async Task SeedOrdersAsync(ApplicationDbContext context, ILogger logger)
        {
            if (!await context.Set<Order>().AnyAsync())
            {
                logger.LogInformation("Seeding orders");

                var customers = await context.Customers.ToListAsync();
                var hotels = await context.Hotels.ToListAsync();

                if (customers.Any() && hotels.Any())
                {
                    var orders = new List<Order>
                    {
                        new Order
                        {
                            CustomerId = customers[0].Id,
                            HotelId = hotels[0].Id,
                            CheckInDate = DateTime.Now.AddDays(30),
                            CheckOutDate = DateTime.Now.AddDays(37),
                            TotalPrice = hotels[0].PricePerNight * 7
                        },
                        new Order
                        {
                            CustomerId = customers.Count > 1 ? customers[1].Id : customers[0].Id,
                            HotelId = hotels.Count > 1 ? hotels[1].Id : hotels[0].Id,
                            CheckInDate = DateTime.Now.AddDays(45),
                            CheckOutDate = DateTime.Now.AddDays(50),
                            TotalPrice = (hotels.Count > 1 ? hotels[1].PricePerNight : hotels[0].PricePerNight) * 5
                        }
                    };

                    await context.Set<Order>().AddRangeAsync(orders);
                    await context.SaveChangesAsync();
                    logger.LogInformation("Orders seeded successfully");
                }
                else
                {
                    logger.LogWarning("No customers or hotels found to create orders");
                }
            }
        }
    }
}