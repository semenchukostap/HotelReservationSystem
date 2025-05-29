using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class ApplicationUser : IdentityUser
{
    [Required(ErrorMessage = "Phone number is required")]
    [MaxLength(15)]
    public override string? PhoneNumber { get; set; }

    public ICollection<Order> Orders { get; set; } = new List<Order>();
}