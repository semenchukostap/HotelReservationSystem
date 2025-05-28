using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Models;

public class Order
{
    public int Id { get; set; }

    [Required]
    public Customer Customer { get; set; } = null!;
    
    [Required]
    public int CustomerId { get; set; }
    
    [Required]
    public Hotel Hotel { get; set; } = null!;

    [Required]
    public int HotelId { get; set; }

    [Required]
    public DateTime DateOrdered { get; set; }

    [Required]
    public DateTime StartDate { get; set; }

    [Required]
    public DateTime EndDate { get; set; }

    [Required]
    public int NumberOfDays { get; set; }

    [Required]
    public double FullPrice { get; set; }
}