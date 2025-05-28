using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace HotelReservationSystem.Models
{
    public class Order
    {
        public int Id { get; set; }

        [Required]
        [ValidateNever]
        public required Customer Customer { get; set; }
        
        [Required]
        [ValidateNever]
        public required Hotel Hotel { get; set; }

        [Required]
        [DataType(DataType.Date)]
        [Display(Name = "Order Date")]
        public DateTime DateOrdered { get; set; }

        [Required]
        [DataType(DataType.Date)]
        [Display(Name = "Check-in Date")]
        public DateTime StartDate { get; set; }

        [Required]
        [DataType(DataType.Date)]
        [Display(Name = "Check-out Date")]
        public DateTime EndDate { get; set; }

        [Display(Name = "Number of Days")]
        public int NumberOfDays { get; set; }

        [Display(Name = "Total Price")]
        [DataType(DataType.Currency)]
        public double FullPrice { get; set; }
    }
}