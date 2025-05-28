using HotelReservationSystem.Models;
using System;
using System.Collections.Generic;

namespace HotelReservationSystem.ViewModels
{
    public class HotelViewModel
    {
        public Hotel? Hotel { get; set; }
        public IEnumerable<Country>? Countries { get; set; }
        
        public string Title => Hotel?.Id != 0 ? "Edit Hotel" : "New Hotel";
    }
}