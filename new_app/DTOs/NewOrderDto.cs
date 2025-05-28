namespace HotelReservationSystem.DTOs;

public class NewOrderDto
{
    public int HotelId { get; set; }
    public DateTime StayStart { get; set; }
    public int DaysOfStay { get; set; }
}