using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Order
    {
        public int Id { get; set; }
        
        // Navigation property
        public Customer Customer { get; set; }
        
        [Required]
        public int CustomerId { get; set; }
        
        // Navigation property
        public Hotel Hotel { get; set; }
        
        [Required]
        public int HotelId { get; set; }

        [Required]
        public DateTime DateOrdered { get; set; }

        [Required]
        public DateTime StartDate { get; set; }

        [Required]
        public DateTime EndDate { get; set; }

        public int NumberOfDays { get; set; }

        public double FullPrice { get; set; }
    }
}