using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.Mappings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Microsoft.AspNetCore.Http.Json;
using System.Text.Json.Serialization;

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("logs/hotel_reservation.log", rollingInterval: RollingInterval.Day)
    .CreateBootstrapLogger();

try
{
    // Setup builder with Serilog
    var builder = WebApplication.CreateSlimBuilder(args);
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext());

    // Configuration
    builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
    builder.Configuration.AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true);
    builder.Configuration.AddEnvironmentVariables();

    if (builder.Environment.IsDevelopment())
    {
        builder.Configuration.AddUserSecrets<Program>();
    }

    // Add services to the container
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
        ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

    // Configure DbContext with SQL Server
    builder.Services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(connectionString, sqlOptions =>
        {
            sqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(30),
                errorNumbersToAdd: null);
        }));

    builder.Services.AddDatabaseDeveloperPageExceptionFilter();

    // Configure Identity with modern options
    builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => 
    {
        options.SignIn.RequireConfirmedAccount = false;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 8;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.MaxFailedAccessAttempts = 5;
    })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

    // Configure authentication and cookie policy
    builder.Services.AddAuthentication()
        .AddCookie(IdentityConstants.ApplicationScheme, options =>
        {
            options.LoginPath = "/Identity/Account/Login";
            options.LogoutPath = "/Identity/Account/Logout";
            options.AccessDeniedPath = "/Identity/Account/AccessDenied";
            options.SlidingExpiration = true;
            options.ExpireTimeSpan = TimeSpan.FromHours(2);
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
        });

    // Configure Authorization Policies
    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
        options.AddPolicy("RequireManagerRole", policy => policy.RequireRole("Manager"));
        options.AddPolicy("RequireUserRole", policy => policy.RequireRole("User"));
    });

    // Add AutoMapper with custom profile
    builder.Services.AddAutoMapper(typeof(AutoMapperProfile));

    // Add Controllers with Views and API support using System.Text.Json
    builder.Services.AddControllersWithViews()
        .AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
            options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
            options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
        });

    // Add Razor Pages support
    builder.Services.AddRazorPages();

    // Add Memory Cache and Distributed Cache
    builder.Services.AddMemoryCache();
    builder.Services.AddDistributedMemoryCache();

    // Add Session support
    builder.Services.AddSession(options =>
    {
        options.IdleTimeout = TimeSpan.FromMinutes(30);
        options.Cookie.HttpOnly = true;
        options.Cookie.IsEssential = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    });

    // CORS policy
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowSpecificOrigins",
            policy =>
            {
                policy.WithOrigins("https://localhost:7000")
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
    });

    // Configure Performance and other options
    builder.Services.Configure<RouteOptions>(options =>
    {
        options.LowercaseUrls = true;
        options.AppendTrailingSlash = false;
    });

    // Health checks
    builder.Services.AddHealthChecks()
        .AddDbContextCheck<ApplicationDbContext>()
        .AddCheck<MemoryHealthCheck>("Memory");

    // Build the app
    var app = builder.Build();

    // Configure the HTTP request pipeline
    if (app.Environment.IsDevelopment())
    {
        app.UseMigrationsEndPoint();
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        app.UseStatusCodePagesWithReExecute("/Home/Error/{0}");
        app.UseHsts();
    }

    // Request logging middleware
    app.UseSerilogRequestLogging();

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseCookiePolicy();
    app.UseSession();

    // Use CORS before routing
    app.UseCors("AllowSpecificOrigins");

    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    // API endpoints
    app.MapHealthChecks("/health");
    
    // Configure routes
    app.MapControllerRoute(
        name: "areas",
        pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");

    app.MapRazorPages();

    // Initialize database and seed roles
    await InitializeDatabaseAsync(app);

    // Start the application
    await app.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

// Method to initialize database
async Task InitializeDatabaseAsync(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        await context.Database.MigrateAsync();
            
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            
        // Seed roles if they don't exist
        string[] roleNames = { "Admin", "Manager", "User" };
        foreach (var roleName in roleNames)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdentityRole(roleName));
            }
        }

        // Check for admin user and create if not exists
        var adminEmail = app.Configuration["AdminUser:Email"];
        if (!string.IsNullOrEmpty(adminEmail))
        {
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true
                };
                var password = app.Configuration["AdminUser:Password"];
                var result = await userManager.CreateAsync(adminUser, password ?? "Admin@123456");
                
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                }
            }
        }
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}

// Health check class
public class MemoryHealthCheck : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    public Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context, 
        CancellationToken cancellationToken = default)
    {
        var allocated = GC.GetTotalMemory(forceFullCollection: false);
        var memoryInfo = Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy("Memory within parameters", 
            new Dictionary<string, object> { { "AllocatedBytes", allocated } });
        
        return Task.FromResult(memoryInfo);
    }
}

// Make the implicit Program class public for testing
public partial class Program { }
