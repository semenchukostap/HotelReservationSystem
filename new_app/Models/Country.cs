using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class Country
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    [Display(Name = "Country Name")]
    public required string Name { get; set; }
}