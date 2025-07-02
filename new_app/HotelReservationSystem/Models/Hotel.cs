namespace HotelReservationSystem.Models;

public class Hotel
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public int CountryId { get; set; }
    public decimal PricePerNight { get; set; }
    public int Rating { get; set; }
    public virtual Country Country { get; set; } = null!;
    public virtual ICollection<Order> Orders { get; set; } = new List<Order>();
}