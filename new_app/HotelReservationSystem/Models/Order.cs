namespace HotelReservationSystem.Models;

public class Order
{
    public int Id { get; set; }
    public DateTime DateCreated { get; set; }
    public DateTime CheckInDate { get; set; }
    public DateTime CheckOutDate { get; set; }
    public int HotelId { get; set; }
    public virtual Hotel Hotel { get; set; } = null!;
    public string CustomerId { get; set; } = string.Empty;
    public virtual ApplicationUser Customer { get; set; } = null!;
    public decimal TotalPrice { get; set; }
    public OrderStatus Status { get; set; }
}

public enum OrderStatus
{
    Pending,
    Confirmed,
    Cancelled,
    Completed
}