using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class Customer
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    public DateTime? BirthDate { get; set; }

    public bool IsSubscribedToNewsletter { get; set; }
}