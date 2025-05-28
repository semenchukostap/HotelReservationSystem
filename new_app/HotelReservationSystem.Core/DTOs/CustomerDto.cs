using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.DTOs
{
    public class CustomerDto
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string Name { get; set; } = string.Empty;

        public DateTime? Birthdate { get; set; }
    }
}