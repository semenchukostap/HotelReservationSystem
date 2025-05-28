using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;

namespace HotelReservationSystem.Core.Models
{
    public class Country
    {
        public int Id { get; set; }
        
        [Required]
        [StringLength(255)]
        public string Name { get; set; } = string.Empty;
        
        public ICollection<Hotel>? Hotels { get; set; }
    }
}