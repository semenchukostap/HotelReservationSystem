using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    public class CustomerViewModel
    {
        public int? Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string? Name { get; set; }

        [DataType(DataType.Date)]
        [Display(Name = "Date of Birth")]
        public DateTime? Birthdate { get; set; }

        public string Title => Id.HasValue ? "Edit Customer" : "New Customer";
    }
}