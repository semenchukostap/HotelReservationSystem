using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.DTOs;

public class NewOrderDto
{
    [Required]
    public int HotelId { get; set; }

    [Required]
    public int CustomerId { get; set; }

    [Required]
    [Display(Name = "Start Date")]
    public DateTime StartDate { get; set; }

    [Required]
    [Display(Name = "End Date")]
    public DateTime EndDate { get; set; }
}