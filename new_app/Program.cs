using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.Mappings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
ConfigureServices(builder.Services, builder.Configuration, builder.Environment);

var app = builder.Build();

// Configure the HTTP request pipeline.
ConfigureMiddleware(app, app.Environment);

// Database initialization
InitializeDatabase(app);

app.Run();

// Helper methods for organizing the configuration
void ConfigureServices(IServiceCollection services, IConfiguration configuration, IWebHostEnvironment env)
{
    // Configure database context
    var connectionString = configuration.GetConnectionString("DefaultConnection") ?? 
        throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
    
    services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(connectionString));
    
    services.AddDatabaseDeveloperPageExceptionFilter();

    // Configure Identity
    services.AddDefaultIdentity<ApplicationUser>(options => 
    {
        // Password settings - similar to the legacy app
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequiredLength = 6;

        // Lockout settings - similar to the legacy app
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
        
        // User settings
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedAccount = false;
    })
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>();
    
    // Add authorization policies
    services.AddAuthorization(options =>
    {
        options.AddPolicy("CanManageHotels", policy =>
            policy.RequireRole(RoleName.CanManageHotels));
        options.AddPolicy("RequireAdministratorRole", policy =>
            policy.RequireRole(RoleName.Admin));
    });

    // Add AutoMapper
    services.AddAutoMapper(typeof(AutoMapperProfile));

    // Add controllers with Newtonsoft.Json support for better compatibility
    services.AddControllersWithViews(options =>
    {
        // Apply authorization globally - similar to FilterConfig
        options.Filters.Add(new AuthorizeFilter());
        
        // Handle errors - similar to HandleErrorAttribute
        options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
    })
    .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
    });
    
    // Add Razor Pages (used by Identity)
    services.AddRazorPages();

    // Add HttpContext accessor
    services.AddHttpContextAccessor();
    
    // Configure Email services (replaces legacy EmailService)
    services.AddTransient<IEmailSender, EmailSender>();
}

void ConfigureMiddleware(WebApplication app, IWebHostEnvironment env)
{
    // Configure the HTTP request pipeline.
    if (env.IsDevelopment())
    {
        app.UseMigrationsEndPoint();
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler("/Home/Error");
        // The default HSTS value is 30 days
        app.UseHsts();
    }

    // Use HTTPS - equivalent to RequireHttpsAttribute in legacy app
    app.UseHttpsRedirection();
    
    // Serve static files from wwwroot
    app.UseStaticFiles();

    app.UseRouting();

    // Enable authentication and authorization
    app.UseAuthentication();
    app.UseAuthorization();

    // Map controllers and Razor Pages
    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");
    app.MapRazorPages();
}

void InitializeDatabase(WebApplication app)
{
    // Create a scope to obtain scoped services
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        try
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
            
            // Ensure database is created and migrate if needed
            context.Database.Migrate();
            
            // Seed initial data, roles and users
            DbInitializer.Initialize(services, app.Environment).Wait();
        }
        catch (Exception ex)
        {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "An error occurred while seeding the database.");
        }
    }
}