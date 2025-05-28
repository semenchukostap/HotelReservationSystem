using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.DTOs;

public class OrderDto
{
    public int Id { get; set; }
    
    public int HotelId { get; set; }
    public string HotelName { get; set; } = string.Empty;
    
    public int CustomerId { get; set; }
    public string CustomerName { get; set; } = string.Empty;
    
    public DateTime ReservationDate { get; set; }
    
    [Display(Name = "Start Date")]
    public DateTime StartDate { get; set; }
    
    [Display(Name = "End Date")]
    public DateTime EndDate { get; set; }
    
    public int NumberOfDays { get; set; }
    
    public decimal FullPrice { get; set; }
}