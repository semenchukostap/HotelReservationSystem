using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models.AccountViewModels;

public class ExternalLoginConfirmationViewModel
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
}