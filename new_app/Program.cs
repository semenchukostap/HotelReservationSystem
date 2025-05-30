using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.Mappings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using Microsoft.AspNetCore.Diagnostics;

var builder = WebApplication.CreateBuilder(args);

// Set default global JSON serialization options
builder.Services.ConfigureHttpJsonOptions(options => {
    options.SerializerOptions.WriteIndented = true;
    options.SerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    options.SerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
});

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? 
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString, sqlServerOptions =>
        sqlServerOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorNumbersToAdd: null)));

builder.Services.AddDatabaseDeveloperPageExceptions();

// Configure identity services - migrated from IdentityConfig.cs and Startup.Auth.cs
builder.Services.AddDefaultIdentity<ApplicationUser>(options => {
    options.SignIn.RequireConfirmedAccount = false;
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedPhoneNumber = false;
    
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    
    // User lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
})
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Add Authentication services (migrated from Startup.Auth.cs)
builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddCookie(IdentityConstants.ApplicationScheme, options => {
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromDays(14);
    options.SlidingExpiration = true;
});

// Configure authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanManageHotels", policy =>
        policy.RequireRole(RoleName.CanManageHotels));
    
    options.AddPolicy("RequireAdministratorRole", policy =>
        policy.RequireRole(RoleName.Administrator));
});

// Add AutoMapper - migrated from MappingProfile.cs in App_Start
builder.Services.AddAutoMapper(cfg => {
    cfg.AddProfile<AutoMapperProfiles>();
}, typeof(Program).Assembly);

// Add email and SMS services - migrated from IdentityConfig.cs
builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddTransient<ISmsSender, SmsSender>();

// Add custom application services
builder.Services.AddScoped<IBookingService, BookingService>();
builder.Services.AddScoped<IHotelService, HotelService>();

builder.Services.AddControllersWithViews(options => {
    // Add global filters if needed
    // options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
})
.AddJsonOptions(options =>
{
    options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    options.JsonSerializerOptions.WriteIndented = true;
    options.JsonSerializerOptions.ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
});

builder.Services.AddRazorPages();

// Add API controllers with routing - migrated from WebApiConfig.cs
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => {
    options.SwaggerDoc("v1", new() { Title = "Hotel Reservation API", Version = "v1" });
});

// Add typed HTTP clients for API communication if needed
builder.Services.AddHttpClient();

// Add session state
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options => {
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// Add output caching
builder.Services.AddOutputCache(options =>
{
    options.AddBasePolicy(builder => 
        builder.Cache()
        .Expire(TimeSpan.FromMinutes(10))
    );
});

// Add ApplicationInsights
builder.Services.AddApplicationInsightsTelemetry();

// Add CORS policy
builder.Services.AddCors(options => {
    options.AddDefaultPolicy(policy => {
        policy.WithOrigins("https://localhost:44349")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

// Configure HttpsRedirection using same port as original app
builder.Services.AddHttpsRedirection(options =>
{
    options.HttpsPort = 44349;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
    
    // Add Swagger in development environment
    app.UseSwagger();
    app.UseSwaggerUI(options => {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "Hotel Reservation API v1");
    });
}
else
{
    app.UseExceptionHandler(errorApp => {
        errorApp.Run(async context => {
            context.Response.StatusCode = 500;
            context.Response.ContentType = "text/html";
            
            var exceptionHandlerPathFeature = 
                context.Features.Get<IExceptionHandlerPathFeature>();
            
            // Log error
            var logger = app.Services.GetRequiredService<ILogger<Program>>();
            logger.LogError(exceptionHandlerPathFeature?.Error, 
                "An unhandled exception occurred while processing the request");
                
            await context.Response.WriteAsync("<html><body><h2>Error: An unexpected error occurred</h2></body></html>");
        });
    });
    
    // The default HSTS value is 30 days.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseCors();
app.UseRouting();
app.UseSession();
app.UseOutputCache();

app.UseAuthentication();
app.UseAuthorization();

// Define routes from RouteConfig.cs
app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

// Map API routes - migrated from WebApiConfig.cs
app.MapControllerRoute(
    name: "api",
    pattern: "api/{controller}/{id?}");

// Map minimal API endpoints if needed
app.MapGet("/api/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
    .WithName("HealthCheck")
    .WithOpenApi()
    .CacheOutput(policy => policy.Expire(TimeSpan.FromMinutes(5)));

// Initialize and seed the database
if (app.Environment.IsDevelopment())
{
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        try
        {
            var context = services.GetRequiredService<ApplicationDbContext>();
            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
            
            // Initialize database with seed data
            await context.Database.MigrateAsync();
            await ApplicationDbInitializer.SeedData(userManager, roleManager, context);
        }
        catch (Exception ex)
        {
            var logger = services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "An error occurred while seeding the database.");
        }
    }
}

// Enable problem details for error handling
app.UseStatusCodePages(async statusCodeContext => {
    // Log 404s and other status codes
    if (statusCodeContext.HttpContext.Response.StatusCode == 404)
    {
        var logger = app.Services.GetRequiredService<ILogger<Program>>();
        logger.LogWarning("404 error occurred for path: {Path}", statusCodeContext.HttpContext.Request.Path);
    }
    
    await statusCodeContext.HttpContext.Response.WriteAsync(
        $"Status Code: {statusCodeContext.HttpContext.Response.StatusCode}");
});

app.Run();

// Make the Program class public for testing
public partial class Program { }