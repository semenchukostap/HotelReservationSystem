using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Models;

public class ApplicationUser : IdentityUser
{
    [Required]
    [MaxLength(20)]
    public required string Phone { get; set; }
}