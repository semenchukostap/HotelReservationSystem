using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Models;

public class Order
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [ForeignKey("Hotel")]
    public int HotelId { get; set; }

    [Required]
    public Hotel? Hotel { get; set; }

    [ForeignKey("User")]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public ApplicationUser? User { get; set; }

    [Required]
    [Display(Name = "Check-in Date")]
    [DataType(DataType.Date)]
    public DateTime StayStart { get; set; }

    [Required]
    [Display(Name = "Number of Days")]
    [Range(1, 365, ErrorMessage = "Stay duration must be between 1 and 365 days")]
    public int DaysOfStay { get; set; }

    [Required]
    [Display(Name = "Total Price")]
    [DataType(DataType.Currency)]
    [Column(TypeName = "decimal(18, 2)")]
    public double FullPrice { get; set; }

    [Display(Name = "Booking Date")]
    [DataType(DataType.DateTime)]
    public DateTime BookingDate { get; set; } = DateTime.Now;
}