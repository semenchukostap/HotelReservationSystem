using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for confirming external login information
    /// </summary>
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(20)]
        [Display(Name = "Phone Number")]
        public string Phone { get; set; }

        [Display(Name = "First Name")]
        [StringLength(50)]
        public string FirstName { get; set; }

        [Display(Name = "Last Name")]
        [StringLength(50)]
        public string LastName { get; set; }
    }

    /// <summary>
    /// View model for external login process
    /// </summary>
    public class ExternalLoginViewModel
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        public string ReturnUrl { get; set; }

        public string Email { get; set; }
    }

    /// <summary>
    /// View model for listing external login providers
    /// </summary>
    public class ExternalLoginListViewModel
    {
        public string ReturnUrl { get; set; }
        public bool ShowRememberMe { get; set; }
    }
}