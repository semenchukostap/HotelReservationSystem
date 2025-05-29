using HotelReservationSystem.Models;
using System;
using System.Collections.Generic;
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
        public DateTime StartDate { get; set; }
        
        [Required]
        [Display(Name = "End Date")]
        public DateTime EndDate { get; set; }
    }
}