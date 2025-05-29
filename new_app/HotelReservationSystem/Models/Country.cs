using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models
{
    public class Country
    {
        public int Id { get; set; }

        [Required]
        [StringLength(100)]
        public string Name { get; set; } = null!;

        [Required]
        [StringLength(2)]
        public string Code { get; set; } = null!;

        public ICollection<Hotel> Hotels { get; set; } = new List<Hotel>();
    }