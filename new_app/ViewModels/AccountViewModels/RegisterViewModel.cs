using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels.AccountViewModels
{
    /// <summary>
    /// View model for handling user registration data
    /// Contains email, phone, and password information for new user accounts
    /// </summary>
    public class RegisterViewModel
    {
        /// <summary>
        /// User email address - used for authentication and communication
        /// </summary>
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public required string Email { get; set; } = string.Empty;

        /// <summary>
        /// User phone number - used for verification and account recovery
        /// </summary>
        [Required]
        [StringLength(20, ErrorMessage = "The {0} must be between {2} and {1} characters long.", MinimumLength = 6)]
        [Display(Name = "Phone")]
        public required string Phone { get; set; } = string.Empty;

        /// <summary>
        /// User password - must meet minimum security requirements
        /// </summary>
        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be between {2} and {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public required string Password { get; set; } = string.Empty;

        /// <summary>
        /// Confirmation of user password - must match Password property
        /// </summary>
        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public required string ConfirmPassword { get; set; } = string.Empty;
    }
}
