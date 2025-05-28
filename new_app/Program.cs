using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Text.Json.Serialization;
using AutoMapper;
using new_app.Data;
using new_app.Models;
using new_app.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container

// Configure database connection
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? 
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

// Add DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Add Identity
builder.Services.AddDefaultIdentity<ApplicationUser>(options => {
    options.SignIn.RequireConfirmedAccount = false;
    
    // Configure password requirements (migrated from IdentityConfig.cs)
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 6;
    
    // Configure user lockout (migrated from IdentityConfig.cs)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

// Configure Identity Cookie settings (migrated from Startup.Auth.cs)
builder.Services.ConfigureApplicationCookie(options => {
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Add external authentication providers - commented out until credentials are provided
// These can be enabled later by uncommenting and configuring in appsettings.json
/*
builder.Services.AddAuthentication()
    .AddFacebook(options => {
        options.AppId = builder.Configuration["Authentication:Facebook:AppId"];
        options.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
    })
    .AddGoogle(options => {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    })
    .AddMicrosoftAccount(options => {
        options.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"];
    })
    .AddTwitter(options => {
        options.ConsumerKey = builder.Configuration["Authentication:Twitter:ConsumerKey"];
        options.ConsumerSecret = builder.Configuration["Authentication:Twitter:ConsumerSecret"];
    });
*/

// Add Email and SMS services for Identity (migrated from IdentityConfig.cs)
builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddTransient<ISmsSender, SmsSender>();

// Add AutoMapper (migrated from MappingProfile.cs)
builder.Services.AddAutoMapper(typeof(AutoMapperProfile));

// Add controllers with options
builder.Services.AddControllersWithViews(options => {
    // Apply global filters (migrated from FilterConfig.cs)
    options.Filters.Add(new Microsoft.AspNetCore.Mvc.AuthorizeFilter());
    options.Filters.Add(new Microsoft.AspNetCore.Mvc.RequireHttpsAttribute());
})
.AddJsonOptions(options => {
    // Handle reference loops in JSON serialization
    options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});

// Add Razor Pages (needed for Identity UI)
builder.Services.AddRazorPages();

// Add Application Insights (migrated from Web.config module)
builder.Services.AddApplicationInsightsTelemetry();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseMigrationsEndPoint(); // For EF Core migration errors
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

// Configure routes (migrated from RouteConfig.cs)
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// API routes (migrated from WebApiConfig.cs)
app.MapControllerRoute(
    name: "api",
    pattern: "api/{controller}/{id?}");

app.MapRazorPages();

// Optional: Database seeding
// This can be done here or in a separate DbInitializer class
/*
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        
        // Call your DbInitializer here
        // await DbInitializer.InitializeAsync(context, userManager, roleManager);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}
*/

app.Run();

// Email and SMS service interfaces and implementations (migrated from IdentityConfig.cs)
public interface IEmailSender
{
    Task SendEmailAsync(string email, string subject, string message);
}

public interface ISmsSender
{
    Task SendSmsAsync(string number, string message);
}

public class EmailSender : IEmailSender
{
    public Task SendEmailAsync(string email, string subject, string message)
    {
        // Implement email sending logic here
        return Task.CompletedTask;
    }
}

public class SmsSender : ISmsSender
{
    public Task SendSmsAsync(string number, string message)
    {
        // Implement SMS sending logic here
        return Task.CompletedTask;
    }
}