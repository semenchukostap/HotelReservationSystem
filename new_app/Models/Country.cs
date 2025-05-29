namespace HotelReservationSystem.Features.Common.Domain;

public class Country
{
    public int Id { get; set; }
    
    public required string Name { get; set; }

    public virtual ICollection<Hotel> Hotels { get; init; } = new List<Hotel>();
}