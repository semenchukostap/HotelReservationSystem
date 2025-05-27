using System;
using Microsoft.Extensions.Configuration;

namespace HotelReservationSystem.Hidden
{
    public static class AdminCredentials
    {
        private static IConfiguration _configuration;

        static AdminCredentials()
        {
            // Initialize the configuration to read from appsettings or environment variables
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables();
            _configuration = builder.Build();
        }

        /// <summary>
        /// Retrieves the admin login from the configuration settings.
        /// </summary>
        public static string Login => _configuration["AdminCredentials:Login"] ?? throw new InvalidOperationException("Admin login is not configured.");

        /// <summary>
        /// Retrieves the admin password from the configuration settings.
        /// </summary>
        public static string Password => _configuration["AdminCredentials:Password"] ?? throw new InvalidOperationException("Admin password is not configured.");
    }
}