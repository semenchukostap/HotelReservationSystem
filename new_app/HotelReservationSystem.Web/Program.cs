using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Data;
using HotelReservationSystem.Services;
using HotelReservationSystem.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// 1. Database Configuration
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? 
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// 2. Identity Configuration
builder.Services.AddDefaultIdentity<ApplicationUser>(options => {
        options.SignIn.RequireConfirmedAccount = true;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequiredLength = 6;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

// 3. Authorization Configuration
builder.Services.AddAuthorization(options => {
    options.AddPolicy("CanManageHotels", policy =>
        policy.RequireRole(RoleConstants.Admin));
    options.AddPolicy("ViewReservations", policy =>
        policy.RequireRole(RoleConstants.Admin, RoleConstants.Staff));
    options.AddPolicy("ManageUsers", policy =>
        policy.RequireRole(RoleConstants.Admin));
    options.AddPolicy("CreateBooking", policy =>
        policy.RequireAuthenticatedUser());
});

// 4. External Authentication Configuration
/*
builder.Services.AddAuthentication()
    .AddFacebook(options =>
    {
        options.AppId = builder.Configuration["Authentication:Facebook:AppId"];
        options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
    })
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    });
*/

// 5. MVC and API Configuration
builder.Services.AddControllersWithViews()
    .AddJsonOptions(options => {
        options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.Preserve;
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.JsonSerializerOptions.WriteIndented = true;
    });

// 6. Razor Pages Configuration
builder.Services.AddRazorPages();

// 7. AutoMapper Configuration
builder.Services.AddAutoMapper(typeof(MappingProfile));

// 8. Application Services Registration
builder.Services.AddScoped<IHotelService, HotelService>();
builder.Services.AddScoped<ICustomerService, CustomerService>();
builder.Services.AddScoped<IOrderService, OrderService>();
builder.Services.AddScoped<ICountryService, CountryService>();

var app = builder.Build();

// 9. HTTP Request Pipeline Configuration
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// 10. Endpoint Configuration
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
    
app.MapRazorPages();

// 11. Database Initialization
using (var scope = app.Services.CreateScope())
{
    try
    {
        var services = scope.ServiceProvider;
        var dbContext = services.GetRequiredService<ApplicationDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var logger = services.GetRequiredService<ILogger<Program>>();
        
        logger.LogInformation("Starting database initialization");
        await DbInitializer.Initialize(dbContext, userManager, roleManager);
        logger.LogInformation("Database initialization completed successfully");
    }
    catch (Exception ex)
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while initializing the database");
        
        if (app.Environment.IsDevelopment())
        {
            throw; // Re-throw in development for immediate feedback
        }
    }
}

app.Run();