namespace HotelReservationSystem.Models;

public class Country
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public virtual ICollection<Hotel> Hotels { get; set; } = new List<Hotel>();
}