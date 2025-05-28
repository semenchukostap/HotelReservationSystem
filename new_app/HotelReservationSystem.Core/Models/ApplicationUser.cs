using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(20)]
        public string Phone { get; set; } = string.Empty;
        
        public ICollection<Order>? Orders { get; set; }
    }
}