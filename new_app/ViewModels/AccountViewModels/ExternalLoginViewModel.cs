using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class ExternalLoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(20, ErrorMessage = "The {0} must be at most {1} characters long.")]
        public string Phone { get; set; } = string.Empty;
    }
}