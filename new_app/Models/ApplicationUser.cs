using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Web.Models;

public class ApplicationUser : IdentityUser
{
    public string? PhoneNumber { get; set; }
    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
}