using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents an application user with extended identity properties
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [StringLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(50)]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [StringLength(20)]
        public string Phone { get; set; } = string.Empty;

        public DateTime Created { get; set; } = DateTime.UtcNow;

        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Gets the full name of the user
        /// </summary>
        public string FullName => $"{FirstName} {LastName}".Trim();
    }
}