using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    public class NewOrderDto
    {
        [Required]
        public int CustomerId { get; set; }
        
        [Required]
        public int HotelId { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime StartDate { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime EndDate { get; set; }
    }
}