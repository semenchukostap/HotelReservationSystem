namespace new_app.DTOs;

public class HotelDto
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string CountryName { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public int Stars { get; set; }
    public double PricePerNight { get; set; }
    public bool IsAllInclusive { get; set; }
}
