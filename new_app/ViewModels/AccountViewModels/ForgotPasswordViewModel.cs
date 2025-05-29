using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;
    }
}