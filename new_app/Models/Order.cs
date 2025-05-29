using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Web.Models;

public class Order
{
    public int Id { get; set; }

    [Required]
    public DateTime DateCreated { get; set; }

    [Required]
    public DateTime CheckIn { get; set; }

    [Required]
    public DateTime CheckOut { get; set; }

    public int NumberOfNights { get; set; }

    [Required]
    [Range(0, double.MaxValue)]
    public decimal FullPrice { get; set; }

    [Required]
    public string CustomerId { get; set; } = null!;

    [Required]
    public ApplicationUser Customer { get; set; } = null!;

    [Required]
    public int HotelId { get; set; }

    [Required]
    public Hotel Hotel { get; set; } = null!;
}