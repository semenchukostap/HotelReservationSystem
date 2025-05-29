using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using HotelReservationSystem.Models;
using Microsoft.IdentityModel.Tokens;

namespace HotelReservationSystem.Services
{
    /// <summary>
    /// Service responsible for generating JWT tokens for user authentication.
    /// </summary>
    public class JwtTokenService : IJwtTokenService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<JwtTokenService> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtTokenService"/> class.
        /// </summary>
        /// <param name="configuration">The application configuration.</param>
        /// <param name="logger">The logger instance.</param>
        /// <exception cref="ArgumentNullException">Thrown when configuration or logger is null.</exception>
        public JwtTokenService(IConfiguration configuration, ILogger<JwtTokenService> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Generates a JWT token for the specified user.
        /// </summary>
        /// <param name="user">The application user.</param>
        /// <returns>A JWT token string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when user is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when JWT configuration is invalid.</exception>
        public string GenerateToken(ApplicationUser user)
        {
            ArgumentNullException.ThrowIfNull(user);

            try
            {
                _logger.LogInformation("Generating JWT token for user: {UserId}", user.Id);

                var jwtKey = _configuration["Jwt:Key"] 
                    ?? throw new InvalidOperationException("JWT:Key is not configured");
                var jwtIssuer = _configuration["Jwt:Issuer"] 
                    ?? throw new InvalidOperationException("JWT:Issuer is not configured");
                var jwtAudience = _configuration["Jwt:Audience"] 
                    ?? throw new InvalidOperationException("JWT:Audience is not configured");
                var jwtExpireHours = _configuration["Jwt:ExpireHours"] 
                    ?? throw new InvalidOperationException("JWT:ExpireHours is not configured");

                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Name, user.UserName)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var expires = DateTime.UtcNow.AddHours(Convert.ToDouble(jwtExpireHours));

                var token = new JwtSecurityToken(
                    issuer: jwtIssuer,
                    audience: jwtAudience,
                    claims: claims,
                    expires: expires,
                    signingCredentials: creds
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                _logger.LogInformation("JWT token successfully generated for user: {UserId}", user.Id);

                return tokenString;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating JWT token for user: {UserId}", user.Id);
                throw;
            }
        }
    }
}