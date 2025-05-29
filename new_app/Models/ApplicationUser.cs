using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Models;

/// <summary>
/// Represents an application user with additional custom properties
/// </summary>
public class ApplicationUser : IdentityUser
{
    /// <summary>
    /// Gets or sets the user's phone number.
    /// This is a required field with a maximum length of 50 characters.
    /// </summary>
    [Required(ErrorMessage = "Phone number is required")]
    [Phone(ErrorMessage = "Invalid phone number format")]
    [StringLength(50, ErrorMessage = "Phone number cannot exceed 50 characters")]
    [Display(Name = "Phone Number")]
    public string Phone { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the collection of orders associated with this user
    /// </summary>
    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();

    /// <summary>
    /// Gets or sets the customer profile associated with this user
    /// </summary>
    public virtual Customer? CustomerProfile { get; set; }
}