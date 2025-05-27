using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Customer
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string Name { get; set; }

        public DateTime? Birthdate { get; set; }
        
        // Navigation property - Added for EF Core
        public ICollection<Order> Orders { get; set; } = new List<Order>();
    }
}