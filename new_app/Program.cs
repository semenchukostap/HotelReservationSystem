using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.Mappings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace HotelReservationSystem;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        ConfigureServices(builder.Services, builder.Configuration, builder.Environment);

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        ConfigureMiddleware(app, app.Environment);

        // Seed the database
        await SeedDatabase(app);

        app.Run();
    }

    private static void ConfigureServices(IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        // Add DbContext
        var connectionString = configuration.GetConnectionString("DefaultConnection") ?? 
            throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
        
        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        // Add Identity (replacing OWIN authentication)
        services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                // Password settings (migrated from ApplicationUserManager)
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 6;

                // Lockout settings (migrated from ApplicationUserManager)
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings
                options.User.RequireUniqueEmail = true;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

        // Add Authentication (replacing OWIN authentication)
        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
                options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
                options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddCookie(IdentityConstants.ApplicationScheme, options =>
            {
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.SlidingExpiration = true;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            })
            .AddCookie(IdentityConstants.ExternalScheme, options =>
            {
                options.Cookie.Name = IdentityConstants.ExternalScheme;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            })
            .AddCookie(IdentityConstants.TwoFactorRememberMeScheme, options =>
            {
                options.Cookie.Name = IdentityConstants.TwoFactorRememberMeScheme;
                options.ExpireTimeSpan = TimeSpan.FromDays(14);
            })
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme, options =>
            {
                options.Cookie.Name = IdentityConstants.TwoFactorUserIdScheme;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
            });

        // Email services (replacing EmailService)
        services.AddTransient<IEmailSender, EmailSender>();

        // Add AutoMapper (replacing Mapper.Initialize in Global.asax.cs)
        services.AddAutoMapper(typeof(AutoMapperProfile));

        // Add Controllers with Views and API support (replacing MVC and WebAPI config)
        services.AddControllersWithViews(options =>
        {
            // Add global filters (replacing FilterConfig.RegisterGlobalFilters)
            options.Filters.Add(new Microsoft.AspNetCore.Mvc.AuthorizeFilter());
        })
        .AddNewtonsoftJson(options =>
        {
            options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
        });

        // Add Razor Pages support
        services.AddRazorPages();

        // Configure HTTPS redirection (replacing RequireHttpsAttribute global filter)
        services.AddHttpsRedirection(options =>
        {
            options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
            options.HttpsPort = 44349; // Use your SSL port here
        });

        // Add diagnosis tools (replacing Glimpse)
        if (environment.IsDevelopment())
        {
            services.AddDatabaseDeveloperPageExceptionFilter();
        }
    }

    private static void ConfigureMiddleware(WebApplication app, IWebHostEnvironment environment)
    {
        // Configure the HTTP request pipeline.
        if (environment.IsDevelopment())
        {
            app.UseMigrationsEndPoint();
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Home/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios.
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        // Routing middleware (replacing IgnoreRoute and MapRoute from RouteConfig)
        app.UseRouting();

        // Authentication and authorization middleware (replacing OWIN middleware)
        app.UseAuthentication();
        app.UseAuthorization();

        // Configure endpoints (replacing conventional routes and attribute routes)
        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        // Map Razor Pages for Identity
        app.MapRazorPages();

        // Map API endpoints
        app.MapControllers();
    }

    private static async Task SeedDatabase(WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var services = scope.ServiceProvider;
            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
                
                // Create database if it doesn't exist
                await context.Database.EnsureCreatedAsync();
                
                // Seed application roles and admin user
                await DbInitializer.Initialize(context, userManager, roleManager);
            }
            catch (Exception ex)
            {
                var logger = services.GetRequiredService<ILogger<Program>>();
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }
    }
}
