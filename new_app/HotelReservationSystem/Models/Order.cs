namespace HotelReservationSystem.Models;

public class Order
{
    public int Id { get; set; }

    public required Customer Customer { get; set; } = null!;
    
    public required Hotel Hotel { get; set; } = null!;

    public required DateTime DateOrdered { get; set; }

    public required DateTime StartDate { get; set; }

    public required DateTime EndDate { get; set; }

    public int NumberOfDays { get; set; }

    public double FullPrice { get; set; }
}