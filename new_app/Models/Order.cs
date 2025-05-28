using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class Order
{
    public int Id { get; set; }

    public Hotel? Hotel { get; set; }

    [Required]
    public int HotelId { get; set; }

    public ApplicationUser? User { get; set; }

    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public DateTime StayStart { get; set; }

    [Required]
    public int DaysOfStay { get; set; }

    [Required]
    public double FullPrice { get; set; }
}