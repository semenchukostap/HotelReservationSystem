using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class Customer
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public required string Name { get; set; }

    public DateTime? Birthdate { get; set; }
    
    public ICollection<Order>? Orders { get; set; }
}