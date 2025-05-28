using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class Customer
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    [Display(Name = "Date of Birth")]
    [DataType(DataType.Date)]
    public DateTime? Birthdate { get; set; }
}