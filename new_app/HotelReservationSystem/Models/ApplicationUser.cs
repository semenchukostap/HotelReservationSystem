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
        [Phone]
        [Display(Name = "Phone Number")]
        public string Phone { get; set; }

        /// <summary>
        /// The user's first name.
        /// </summary>
        [Required]
        [MaxLength(50)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        /// <summary>
        /// The user's last name.
        /// </summary>
        [Required]
        [MaxLength(50)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; }

        /// <summary>
        /// The user's address.
        /// </summary>
        [MaxLength(100)]
        public string Address { get; set; }

        /// <summary>
        /// The user's city.
        /// </summary>
        [MaxLength(50)]
        public string City { get; set; }

        /// <summary>
        /// The user's country.
        /// </summary>
        [MaxLength(50)]
        public string Country { get; set; }

        /// <summary>
        /// The date when the user was registered.
        /// </summary>
        public DateTime RegistrationDate { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Flag indicating if the user has verified their email address.
        /// </summary>
        public bool IsEmailVerified { get; set; } = false;

        /// <summary>
        /// Gets the full name of the user.
        /// </summary>
        public string FullName => $"{FirstName} {LastName}";
    }
}