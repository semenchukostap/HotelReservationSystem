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
        /// Generates a claims identity for the user with custom claims
        /// </summary>
        /// <param name="manager">The user manager responsible for creating the identity</param>
        /// <returns>A ClaimsIdentity containing user information and claims</returns>
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Use CreateUserIdentityAsync in .NET 8
            var userIdentity = new ClaimsIdentity(
                await manager.GetClaimsAsync(this),
                IdentityConstants.ApplicationScheme);
            
            // Add custom user claims
            userIdentity.AddClaim(new Claim("UserPhone", Phone));
            userIdentity.AddClaim(new Claim("LastAccessed", DateTime.UtcNow.ToString("o")));
            
            return userIdentity;
        }
    }
}
