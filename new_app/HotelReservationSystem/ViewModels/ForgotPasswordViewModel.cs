using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for the forgot password functionality
    /// </summary>
    public class ForgotPasswordViewModel
    {
        /// <summary>
        /// Gets or sets the email address of the user who forgot their password
        /// </summary>
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;
    }
}