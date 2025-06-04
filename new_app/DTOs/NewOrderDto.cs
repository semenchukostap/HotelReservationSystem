namespace new_app.DTOs;

public class NewOrderDto
{
    public int CustomerId { get; set; }
    public int HotelId { get; set; }
    public DateTime StartDate { get; set; }
    public DateTime EndDate { get; set; }
}
