namespace HotelReservationSystem.Models;

public class Order
{
    public int Id { get; set; }
    public required string UserId { get; set; }
    public required int HotelId { get; set; }
    public required DateTime CheckIn { get; set; }
    public required DateTime CheckOut { get; set; }
    public decimal TotalPrice { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public ApplicationUser User { get; set; } = null!;
    public Hotel Hotel { get; set; } = null!;
}