using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Order
    {
        public int Id { get; set; }

        [Required]
        public Customer Customer { get; set; } = null!;

        [Required]
        [Display(Name = "Customer")]
        public int CustomerId { get; set; }
        
        [Required]
        public Hotel Hotel { get; set; } = null!;

        [Required]
        [Display(Name = "Hotel")]
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