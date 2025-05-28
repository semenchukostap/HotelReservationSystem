using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.Models
{
    public class Customer
    {
        public int Id { get; set; }
        
        [Required]
        [StringLength(255)]
        public string Name { get; set; } = string.Empty;
        
        public bool IsSubscribedToNewsletter { get; set; }
        
        [Required]
        public string UserId { get; set; } = string.Empty;
        
        public ApplicationUser? User { get; set; }
    }
}