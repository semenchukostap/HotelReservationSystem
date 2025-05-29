using AutoMapper;
using HotelReservationSystem.Data;
using HotelReservationSystem.Helpers;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Threading.Tasks;

namespace HotelReservationSystem.Extensions
{
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Adds the application database context to the service collection
        /// </summary>
        public static IServiceCollection AddApplicationDbContext(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    configuration.GetConnectionString("DefaultConnection"),
                    sqlOptions => sqlOptions.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.GetName().Name)));

            return services;
        }

        /// <summary>
        /// Adds and configures ASP.NET Core Identity services
        /// </summary>
        public static IServiceCollection AddIdentityServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // Password settings (equivalent to the old PasswordValidator)
                options.Password.RequiredLength = 6;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;

                // Lockout settings (equivalent to UserLockoutEnabledByDefault)
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

            // Configure the Token Lifespans (equivalent to DataProtectorTokenProvider)
            services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                options.TokenLifespan = TimeSpan.FromHours(3);
            });

            // Configure the application cookie
            services.ConfigureApplicationCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.SlidingExpiration = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                
                // Equivalent to OnValidateIdentity in the old code
                options.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = SecurityStampValidator.ValidatePrincipalAsync
                };
            });

            // Add Two-Factor Authentication (2FA)
            services.AddAuthentication()
                .AddCookie(IdentityConstants.TwoFactorRememberMeScheme, options =>
                {
                    options.Cookie.Name = IdentityConstants.TwoFactorRememberMeScheme;
                    options.ExpireTimeSpan = TimeSpan.FromDays(14); // Remember browser for 14 days
                })
                .AddCookie(IdentityConstants.TwoFactorUserIdScheme, options =>
                {
                    options.Cookie.Name = IdentityConstants.TwoFactorUserIdScheme;
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(5); // Five minutes to complete 2FA
                });

            // Add External Authentication Providers (uncomment and configure as needed)
            /*
            services.AddAuthentication()
                .AddFacebook(options =>
                {
                    options.AppId = configuration["Authentication:Facebook:AppId"];
                    options.AppSecret = configuration["Authentication:Facebook:AppSecret"];
                })
                .AddGoogle(options =>
                {
                    options.ClientId = configuration["Authentication:Google:ClientId"];
                    options.ClientSecret = configuration["Authentication:Google:ClientSecret"];
                })
                .AddMicrosoftAccount(options =>
                {
                    options.ClientId = configuration["Authentication:Microsoft:ClientId"];
                    options.ClientSecret = configuration["Authentication:Microsoft:ClientSecret"];
                })
                .AddTwitter(options =>
                {
                    options.ConsumerKey = configuration["Authentication:Twitter:ConsumerKey"];
                    options.ConsumerSecret = configuration["Authentication:Twitter:ConsumerSecret"];
                });
            */

            return services;
        }

        /// <summary>
        /// Adds core application services and MVC configuration
        /// </summary>
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            // Add controllers with views (MVC)
            services.AddControllersWithViews(options =>
            {
                // Add global authorization filter to require authentication by default
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
                
                // Add anti-forgery token validation
                options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
            })
            .AddJsonOptions(options =>
            {
                // Configure JSON serialization options for API responses
                options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
            })
            .AddRazorRuntimeCompilation(); // Enables runtime compilation of Razor views during development

            // Add Razor Pages (optional, if needed)
            services.AddRazorPages();

            // Configure routing
            services.AddRouting(options =>
            {
                options.LowercaseUrls = true;
                options.AppendTrailingSlash = false;
            });

            // HTTP context accessor for easier access to HttpContext
            services.AddHttpContextAccessor();

            // Add HTTPS enforcement
            services.AddHsts(options =>
            {
                options.Preload = true;
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(60);
            });

            return services;
        }

        /// <summary>
        /// Adds business-specific services to the application
        /// </summary>
        public static IServiceCollection AddApplicationBusinessServices(this IServiceCollection services)
        {
            // Register your custom services here
            services.AddScoped<ICustomerService, CustomerService>();
            services.AddScoped<IHotelService, HotelService>();
            services.AddScoped<IOrderService, OrderService>();
            
            // Add email service
            services.AddTransient<IEmailSender, EmailService>();
            
            // Add SMS service (if needed)
            services.AddTransient<ISmsSender, SmsService>();

            return services;
        }

        /// <summary>
        /// Adds and configures AutoMapper
        /// </summary>
        public static IServiceCollection AddAutoMapperProfiles(this IServiceCollection services)
        {
            services.AddAutoMapper(typeof(MappingProfiles).Assembly);
            return services;
        }

        /// <summary>
        /// Configures CORS policy for the application
        /// </summary>
        public static IServiceCollection AddCorsPolicy(this IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigins", builder =>
                {
                    builder.WithOrigins("https://localhost:5001", "http://localhost:5000") // Add your trusted origins
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .AllowCredentials();
                });
            });

            return services;
        }

        /// <summary>
        /// Adds and configures email services for the application
        /// </summary>
        public static IServiceCollection AddEmailServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Configure email service settings from appsettings.json
            services.Configure<EmailSettings>(configuration.GetSection("EmailSettings"));
            
            return services;
        }

        /// <summary>
        /// Configures authorization policies for the application
        /// </summary>
        public static IServiceCollection AddAuthorizationPolicies(this IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                // Policy for managing hotels
                options.AddPolicy(RoleName.CanManageHotels, policy =>
                {
                    policy.RequireRole(RoleName.CanManageHotels);
                });

                // Add more policies as needed
                // Example:
                // options.AddPolicy("RequireAdministratorRole", policy => policy.RequireRole("Administrator"));
            });

            return services;
        }

        /// <summary>
        /// Adds health checks to monitor application status
        /// </summary>
        public static IServiceCollection AddHealthChecks(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddHealthChecks()
                .AddDbContextCheck<ApplicationDbContext>("database")
                .AddCheck<SystemMemoryHealthCheck>("memory");

            return services;
        }
    }
}