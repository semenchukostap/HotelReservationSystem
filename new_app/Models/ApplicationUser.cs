using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System.Security.Claims;
using System;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents the application user with additional properties and methods
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// The user's phone number
        /// </summary>
        [Required]
        [MaxLength(20)]
        public required string Phone { get; set; }

        /// <summary>
        /// Generates a claims identity for the user with custom claims using modern .NET 8 patterns
        /// </summary>
        /// <returns>A ClaimsIdentity containing user information and claims</returns>
        public ClaimsIdentity GenerateUserIdentity()
        {
            // Create identity using .NET 8 approach
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, Id),
                new Claim(ClaimTypes.Name, UserName ?? string.Empty),
                new Claim(ClaimTypes.Email, Email ?? string.Empty),
                new Claim("UserPhone", Phone),
                new Claim("LastAccessed", DateTime.UtcNow.ToString("o"))
            };
            
            return new ClaimsIdentity(claims, IdentityConstants.ApplicationScheme);
        }
    }
}
