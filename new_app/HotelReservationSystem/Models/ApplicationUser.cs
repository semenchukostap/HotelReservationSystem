using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Models;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime DateRegistered { get; set; }
    public string? Address { get; set; }
    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
}