using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs;

public class NewOrderDto
{
    [Required]
    public int CustomerId { get; set; }
    
    [Required]
    public int HotelId { get; set; }

    [Required]
    public DateTime StartDate { get; set; }

    [Required]
    public DateTime EndDate { get; set; }
}