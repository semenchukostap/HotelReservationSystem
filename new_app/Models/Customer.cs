using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Customer
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        public required string Name { get; set; } = string.Empty;

        public DateTime? Birthdate { get; set; }
    }
}