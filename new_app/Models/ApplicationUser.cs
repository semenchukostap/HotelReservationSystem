using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class ApplicationUser : IdentityUser
{
    [Required]
    [MaxLength(20)]
    public required string Phone { get; set; }
}