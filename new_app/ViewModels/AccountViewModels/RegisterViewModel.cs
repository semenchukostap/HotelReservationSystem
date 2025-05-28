using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels.AccountViewModels
{
    /// <summary>
    /// View model for user registration form
    /// </summary>
    public class RegisterViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public required string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(20, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [Display(Name = "Phone")]
        public required string Phone { get; set; } = string.Empty;

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public required string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public required string ConfirmPassword { get; set; } = string.Empty;
    }
}