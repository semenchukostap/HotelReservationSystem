using Microsoft.AspNetCore.Authentication;

namespace HotelReservationSystem.Extensions
{
    public static class AuthenticationExtensions
    {
        public static IServiceCollection AddExternalAuthenticationServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Facebook Authentication
            services.AddAuthentication()
                .AddFacebook(options =>
                {
                    options.AppId = configuration["Authentication:Facebook:AppId"] ?? "";
                    options.AppSecret = configuration["Authentication:Facebook:AppSecret"] ?? "";
                });

            // Google Authentication
            services.AddAuthentication()
                .AddGoogle(options => 
                {
                    options.ClientId = configuration["Authentication:Google:ClientId"] ?? "";
                    options.ClientSecret = configuration["Authentication:Google:ClientSecret"] ?? "";
                });

            return services;
        }
    }
}