namespace HotelReservationSystem.Models;

using System.ComponentModel.DataAnnotations;

public class Order
{
    [Key]
    public int Id { get; set; }

    [Required]
    public required string CustomerId { get; set; }

    [Required]
    public required int HotelId { get; set; }

    [Required]
    [DataType(DataType.Date)]
    [Display(Name = "Check-in Date")]
    public required DateTime CheckInDate { get; set; }

    [Required]
    [DataType(DataType.Date)]
    [Display(Name = "Check-out Date")]
    public required DateTime CheckOutDate { get; set; }

    [Required]
    [Range(0, 999999.99)]
    [DataType(DataType.Currency)]
    [Display(Name = "Full Price")]
    public decimal FullPrice { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public Customer? Customer { get; set; }
    public Hotel? Hotel { get; set; }
}