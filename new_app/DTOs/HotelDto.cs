namespace HotelReservationSystem.DTOs
{
    public class HotelDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public int CountryId { get; set; }
        public string? CountryName { get; set; }
        public int Stars { get; set; }
        public decimal Price { get; set; }
    }
}