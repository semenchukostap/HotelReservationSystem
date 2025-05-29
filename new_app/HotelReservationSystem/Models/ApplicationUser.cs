using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Extends the base IdentityUser class with additional properties required by the application.
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// The user's phone number. This is separate from PhoneNumber in the base IdentityUser
        /// to maintain compatibility with the legacy application's data model.
        /// </summary>
        [Required]
        [MaxLength(20)]
        public string Phone { get; set; }
    }
}