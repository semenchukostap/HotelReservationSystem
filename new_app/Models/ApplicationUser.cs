using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;

namespace HotelReservationSystem.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Additional properties
        public string? PhoneNumber { get; set; } // Nullable as it was in the original application

        // Navigation properties for related entities
        public virtual ICollection<Order>? Orders { get; set; }
    }
}