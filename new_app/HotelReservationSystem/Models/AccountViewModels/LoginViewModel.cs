using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;

namespace HotelReservationSystem.Models.AccountViewModels;

public class LoginViewModel
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    public required string Password { get; set; }

    [Display(Name = "Remember me?")]
    public bool RememberMe { get; set; }

    public IList<AuthenticationScheme>? ExternalLogins { get; set; }
}