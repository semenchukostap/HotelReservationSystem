using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels.AccountViewModels
{
    /// <summary>
    /// View model for user login form.
    /// </summary>
    public class LoginViewModel
    {
        /// <summary>
        /// Gets or sets the user's email address.
        /// </summary>
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the user's password.
        /// </summary>
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether the user should remain logged in.
        /// </summary>
        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}