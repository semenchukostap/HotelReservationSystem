using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class TestViewModel
    {
        [Required]
        public string TestProperty { get; set; } = string.Empty;
    }
}