using HotelReservationSystem.Models;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class OrderViewModel
    {
        [Required]
        [Display(Name = "Customer")]
        public int CustomerId { get; set; }
        
        public IEnumerable<Customer>? Customers { get; set; }
        
        [Required]
        [Display(Name = "Hotel")]
        public int HotelId { get; set; }
        
        public IEnumerable<Hotel>? Hotels { get; set; }
        
        [Required]
        [Display(Name = "Start Date")]
        [DataType(DataType.Date)]
        public DateTime StartDate { get; set; }
        
        [Required]
        [Display(Name = "End Date")]
        [DataType(DataType.Date)]
        [CustomValidation(typeof(OrderViewModel), nameof(ValidateEndDate))]
        public DateTime EndDate { get; set; }
        
        public static ValidationResult? ValidateEndDate(DateTime endDate, ValidationContext context)
        {
            var instance = (OrderViewModel)context.ObjectInstance;
            if (endDate <= instance.StartDate)
            {
                return new ValidationResult("End date must be after start date");
            }
            return ValidationResult.Success;
        }
    }
}
