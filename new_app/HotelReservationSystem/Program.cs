using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;
using HotelReservationSystem.Services;
using HotelReservationSystem.Helpers;
using Microsoft.Extensions.FileProviders;
using System.IO;
using HotelReservationSystem.Middleware;

namespace HotelReservationSystem;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? 
            throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

        // Database context configuration
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString));

        // Identity configuration
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options => 
        {
            options.SignIn.RequireConfirmedAccount = false;
            options.Password.RequiredLength = 6;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.User.RequireUniqueEmail = true;
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            options.Lockout.MaxFailedAccessAttemptsBeforeLockout = 5;
            options.Lockout.AllowedForNewUsers = true;
        })
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();

        // Authentication and authorization configuration
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/Account/Login";
            options.AccessDeniedPath = "/Account/AccessDenied";
            options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            options.SlidingExpiration = true;
        });

        // Register services
        builder.Services.AddTransient<IEmailSender, EmailSender>();
        builder.Services.AddTransient<ISmsService, SmsService>();
        builder.Services.AddTransient<ICustomerService, CustomerService>();
        builder.Services.AddTransient<IHotelService, HotelService>();
        builder.Services.AddTransient<IOrderService, OrderService>();

        // Add AutoMapper configuration
        builder.Services.AddAutoMapper(typeof(MappingProfiles));

        // Add controllers with views and API controllers
        builder.Services.AddControllersWithViews();

        // Configure API behavior options
        builder.Services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.PropertyNamingPolicy = null;
                options.JsonSerializerOptions.WriteIndented = true;
            });

        // Add API explorer and Swagger for API documentation
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseMigrationsEndPoint();
            app.UseSwagger();
            app.UseSwaggerUI();
        }
        else
        {
            // Production error handling
            app.UseExceptionHandler("/Home/Error");
            
            // The default HSTS value is 30 days. You may want to change this for production scenarios.
            app.UseHsts();
        }

        // Custom global exception handling middleware
        app.UseMiddleware<ErrorHandlingMiddleware>();

        app.UseHttpsRedirection();

        // Configure Static Files Middleware
        // This middleware enables serving static files like CSS, JavaScript, images, etc.
        // Default directory for static files is 'wwwroot'
        app.UseStaticFiles();
        
        // Configure additional static file directories for DataTables and other client-side libraries
        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = new PhysicalFileProvider(
                Path.Combine(builder.Environment.ContentRootPath, "wwwroot", "lib")),
            RequestPath = "/lib"
        });

        // Configure additional directory for DataTables specific files
        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = new PhysicalFileProvider(
                Path.Combine(builder.Environment.ContentRootPath, "wwwroot", "lib", "datatables")),
            RequestPath = "/lib/datatables"
        });

        // Configure default document serving behavior
        app.UseDefaultFiles(new DefaultFilesOptions
        {
            DefaultFileNames = new List<string> { "index.html", "default.html" }
        });

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        // Configure routes
        app.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");

        // Initialize and seed the database
        using (var scope = app.Services.CreateScope())
        {
            var services = scope.ServiceProvider;
            try
            {
                var context = services.GetRequiredService<ApplicationDbContext>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
                
                // Ensure database is created and apply migrations
                context.Database.Migrate();
                
                // Seed initial data if needed
                // SeedData.Initialize(context, userManager, roleManager);
            }
            catch (Exception ex)
            {
                var logger = services.GetRequiredService<ILogger<Program>>();
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }

        app.Run();
    }
}