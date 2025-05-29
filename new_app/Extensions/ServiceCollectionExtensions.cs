using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;
using System.Text.Json;
using HotelReservationSystem.Mappings;
using AutoMapper;

namespace HotelReservationSystem.Extensions
{
    /// <summary>
    /// Extension methods for IServiceCollection to organize service registrations in a cleaner way
    /// instead of having all configurations directly in Program.cs
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Configures database context and related services
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <param name="configuration">Application configuration</param>
        /// <returns>The same service collection for chaining</returns>
        /// <exception cref="InvalidOperationException">Thrown when connection string is not found</exception>
        public static IServiceCollection AddDatabaseServices(this IServiceCollection services, IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString, sqlOptions =>
                {
                    sqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null);
                    sqlOptions.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName);
                }));

            services.AddDatabaseDeveloperPageExceptionFilter();

            return services;
        }

        /// <summary>
        /// Configures Identity services with customized security and user management options
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The same service collection for chaining</returns>
        public static IServiceCollection AddIdentityServices(this IServiceCollection services)
        {
            services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings
                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedAccount = false;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

            return services;
        }

        /// <summary>
        /// Adds MVC services with customized options for the Hotel Reservation System including
        /// anti-forgery protection, JSON serialization settings, and Razor pages
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The same service collection for chaining</returns>
        public static IServiceCollection AddMvcServices(this IServiceCollection services)
        {
            services.AddControllersWithViews(options =>
            {
                options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
            })
            .AddNewtonsoftJson(options =>
            {
                options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
            })
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
                options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            });

            services.AddRazorPages();

            return services;
        }

        /// <summary>
        /// Adds AutoMapper and configures mapping profiles for the application to facilitate
        /// object-to-object mapping throughout the system
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The same service collection for chaining</returns>
        public static IServiceCollection AddAutoMapperServices(this IServiceCollection services)
        {
            services.AddAutoMapper(typeof(AutoMapperProfile).Assembly);
            
            return services;
        }

        /// <summary>
        /// Configures API behavior options including model state validation suppression
        /// to allow for custom handling of validation errors
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The same service collection for chaining</returns>
        public static IServiceCollection AddApiBehaviorServices(this IServiceCollection services)
        {
            services.Configure<ApiBehaviorOptions>(options =>
            {
                options.SuppressModelStateInvalidFilter = true;
            });

            return services;
        }

        /// <summary>
        /// Adds application specific services including email sending, HttpContext access,
        /// and AutoMapper services
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The same service collection for chaining</returns>
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            services.AddScoped<IEmailSender, EmailSender>();
            services.AddHttpContextAccessor();
            
            // Register AutoMapper services
            services.AddAutoMapperServices();
            
            // Register any additional application specific services here
            
            return services;
        }

        /// <summary>
        /// Configures all services for the Hotel Reservation System in one comprehensive method
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <param name="configuration">Application configuration</param>
        /// <returns>The same service collection for chaining</returns>
        public static IServiceCollection AddAllServices(this IServiceCollection services, IConfiguration configuration)
        {
            services
                .AddDatabaseServices(configuration)
                .AddIdentityServices()
                .AddMvcServices()
                .AddApiBehaviorServices()
                .AddApplicationServices();

            return services;
        }
    }
}