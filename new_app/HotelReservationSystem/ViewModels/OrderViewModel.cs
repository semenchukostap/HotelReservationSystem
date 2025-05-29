using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for order form operations
    /// </summary>
    public class OrderViewModel
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Customer is required")]
        public int CustomerId { get; set; }

        [Display(Name = "Customer")]
        public string CustomerName { get; set; }

        [Required(ErrorMessage = "Hotel is required")]
        public int HotelId { get; set; }

        [Display(Name = "Hotel")]
        public string HotelName { get; set; }

        [Required(ErrorMessage = "Start date is required")]
        [Display(Name = "Start Date")]
        [DataType(DataType.Date)]
        public DateTime StartDate { get; set; }

        [Required(ErrorMessage = "End date is required")]
        [Display(Name = "End Date")]
        [DataType(DataType.Date)]
        public DateTime EndDate { get; set; }

        [Display(Name = "Full Price")]
        [DataType(DataType.Currency)]
        public double FullPrice { get; set; }

        [Display(Name = "Date Ordered")]
        [DataType(DataType.DateTime)]
        public DateTime DateOrdered { get; set; } = DateTime.Now;

        [Display(Name = "Number of Days")]
        public int NumberOfDays { get; set; }

        /// <summary>
        /// Method to calculate number of days and full price
        /// </summary>
        /// <param name="pricePerNight">Hotel price per night</param>
        public void CalculateDerivedValues(double pricePerNight)
        {
            NumberOfDays = (EndDate - StartDate).Days;
            // Ensure the number of days is at least 1
            if (NumberOfDays < 1)
                NumberOfDays = 1;
                
            FullPrice = Math.Round(pricePerNight * NumberOfDays, 2);
        }
    }
}