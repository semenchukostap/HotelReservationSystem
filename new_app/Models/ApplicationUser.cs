using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using System.Security.Claims;

namespace HotelReservationSystem.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(20)]
        public required string Phone { get; set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, IdentityConstants.ApplicationScheme);
            
            // Add custom user claims here
            return userIdentity;
        }
    }
}
