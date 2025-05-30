using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Models;

public class ApplicationUser : IdentityUser
{
    [Required]
    [MaxLength(20)]
    public required string Phone { get; set; } = string.Empty;
    
    [MaxLength(100)]
    public string? FirstName { get; set; }
    
    [MaxLength(100)]
    public string? LastName { get; set; }
    
    public DateTime Created { get; set; } = DateTime.UtcNow;
    
    public bool IsActive { get; set; } = true;
}