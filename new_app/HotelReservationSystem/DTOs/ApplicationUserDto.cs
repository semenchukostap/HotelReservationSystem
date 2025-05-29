using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Data transfer object for ApplicationUser entity
    /// </summary>
    public class ApplicationUserDto
    {
        public string Id { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }
        
        [Required]
        public string UserName { get; set; }

        [Required]
        [MaxLength(20)]
        public string Phone { get; set; }

        public bool EmailConfirmed { get; set; }

        public string PhoneNumber { get; set; }
        
        public bool PhoneNumberConfirmed { get; set; }
        
        public bool TwoFactorEnabled { get; set; }
    }
}