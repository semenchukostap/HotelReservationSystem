using Microsoft.AspNetCore.Authorization;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Security
{
    public static class AuthorizationPolicies
    {
        public static void ConfigurePolicies(AuthorizationOptions options)
        {
            // Add a default policy requiring authentication
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();

            // Add role-based policies
            options.AddPolicy("RequireAdminRole", policy => policy.RequireRole(RoleName.Admin));
            options.AddPolicy("RequireUserRole", policy => policy.RequireRole(RoleName.User));
        }
    }
}