using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Data;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Extensions
{
    /// <summary>
    /// Extension methods for IApplicationBuilder to configure middleware components
    /// </summary>
    public static class ApplicationBuilderExtensions
    {
        /// <summary>
        /// Configures the application to use standard middleware components for ASP.NET Core MVC
        /// </summary>
        /// <param name="app">The application builder instance</param>
        /// <returns>The application builder instance</returns>
        public static IApplicationBuilder UseHotelReservationApp(this IApplicationBuilder app)
        {
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            
            app.UseAuthentication();
            app.UseAuthorization();
            
            return app;
        }

        /// <summary>
        /// Configures MVC endpoints and default routing for the application
        /// </summary>
        /// <param name="app">The application builder instance</param>
        /// <returns>The application builder instance</returns>
        public static IApplicationBuilder UseHotelReservationEndpoints(this IApplicationBuilder app)
        {
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                
                // Maps attribute-routed API controllers
                endpoints.MapControllers();
                
                // Add custom area routing if needed
                endpoints.MapAreaControllerRoute(
                    name: "admin_area",
                    areaName: "Admin",
                    pattern: "Admin/{controller=Dashboard}/{action=Index}/{id?}");
                
                // Map Razor Pages if any
                endpoints.MapRazorPages();
            });
            
            return app;
        }

        /// <summary>
        /// Configures middleware for handling database migrations and seeding initial data
        /// </summary>
        /// <param name="app">The application builder instance</param>
        /// <returns>The application builder instance</returns>
        public static IApplicationBuilder UseDatabaseMigration(this IApplicationBuilder app)
        {
            using (var scope = app.ApplicationServices.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                
                // Apply any pending migrations
                dbContext.Database.Migrate();
                
                // Ensure roles exist
                SeedRoles(roleManager).GetAwaiter().GetResult();
                
                // Ensure admin user exists
                SeedAdminUser(userManager).GetAwaiter().GetResult();
            }
            
            return app;
        }

        /// <summary>
        /// Seeds the default roles into the database
        /// </summary>
        private static async Task SeedRoles(RoleManager<IdentityRole> roleManager)
        {
            if (!await roleManager.RoleExistsAsync(RoleName.Admin))
                await roleManager.CreateAsync(new IdentityRole(RoleName.Admin));
                
            if (!await roleManager.RoleExistsAsync(RoleName.User))
                await roleManager.CreateAsync(new IdentityRole(RoleName.User));
                
            if (!await roleManager.RoleExistsAsync(RoleName.Manager))
                await roleManager.CreateAsync(new IdentityRole(RoleName.Manager));
        }

        /// <summary>
        /// Seeds the default admin user into the database
        /// </summary>
        private static async Task SeedAdminUser(UserManager<ApplicationUser> userManager)
        {
            const string adminEmail = "admin@hotel.com";
            const string adminPassword = "Admin@123456";
            
            var admin = await userManager.FindByEmailAsync(adminEmail);
            
            if (admin == null)
            {
                admin = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    EmailConfirmed = true,
                    PhoneNumber = "+380000000000",
                    PhoneNumberConfirmed = true
                };
                
                await userManager.CreateAsync(admin, adminPassword);
                await userManager.AddToRoleAsync(admin, RoleName.Admin);
            }
        }

        /// <summary>
        /// Configures exception handling middleware for the application
        /// </summary>
        /// <param name="app">The application builder instance</param>
        /// <param name="isDevelopment">Flag indicating if the application is running in development mode</param>
        /// <returns>The application builder instance</returns>
        public static IApplicationBuilder UseExceptionHandling(this IApplicationBuilder app, bool isDevelopment)
        {
            if (isDevelopment)
            {
                app.UseDeveloperExceptionPage();
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios.
                app.UseHsts();
            }
            
            return app;
        }
        
        /// <summary>
        /// Configures localization middleware for the application
        /// </summary>
        /// <param name="app">The application builder instance</param>
        /// <returns>The application builder instance</returns>
        public static IApplicationBuilder UseLocalization(this IApplicationBuilder app)
        {
            var supportedCultures = new[] { "en-US", "uk-UA" };
            var localizationOptions = new RequestLocalizationOptions()
                .SetDefaultCulture(supportedCultures[0])
                .AddSupportedCultures(supportedCultures)
                .AddSupportedUICultures(supportedCultures);

            app.UseRequestLocalization(localizationOptions);
            
            return app;
        }
        
        /// <summary>
        /// Configures response compression middleware for the application
        /// </summary>
        /// <param name="app">The application builder instance</param>
        /// <returns>The application builder instance</returns>
        public static IApplicationBuilder UseResponseCompression(this IApplicationBuilder app)
        {
            app.UseResponseCompression();
            
            return app;
        }
    }
}