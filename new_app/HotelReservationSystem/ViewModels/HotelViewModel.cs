namespace HotelReservationSystem.ViewModels;

public class HotelViewModel
{
    public Hotel Hotel { get; set; } = new();
    
    public IEnumerable<Country> Countries { get; set; } = new List<Country>();
}