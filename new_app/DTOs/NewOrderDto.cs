using System.ComponentModel.DataAnnotations;

namespace new_app.DTOs
{
    public class NewOrderDto
    {
        [Required]
        public int CustomerId { get; set; }

        [Required]
        public int HotelId { get; set; }

        [Required]
        public DateTime StartDate { get; set; }

        [Required]
        public DateTime EndDate { get; set; }
    }
}