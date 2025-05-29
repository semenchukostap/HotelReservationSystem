using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model class for user login functionality
    /// </summary>
    public class LoginViewModel
    {
        /// <summary>
        /// Gets or sets the email address used for login
        /// </summary>
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the user password
        /// </summary>
        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether the user should be remembered
        /// </summary>
        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }

        /// <summary>
        /// Gets or sets the return URL after successful login
        /// </summary>
        public string? ReturnUrl { get; set; }
    }
}