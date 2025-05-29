namespace HotelReservationSystem.Models;

public class Hotel
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public required string Address { get; set; }
    public required int CountryId { get; set; }
    public Country Country { get; set; } = null!;
    public decimal PricePerNight { get; set; }
    public ICollection<Order> Orders { get; set; } = new List<Order>();
}