using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Application user class that extends the default ASP.NET Core Identity user
    /// with additional hotel reservation specific properties
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// The user's phone number for contact purposes
        /// </summary>
        [Required]
        [MaxLength(20)]
        public string Phone { get; set; } = string.Empty;
    }
}
