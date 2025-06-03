using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    public class NewOrderDto
    {
        public int CustomerId { get; set; }
        public int HotelId { get; set; }
        
        [Required]
        public DateTime StartDate { get; set; }
        
        [Required]
        public DateTime EndDate { get; set; }
    }
}