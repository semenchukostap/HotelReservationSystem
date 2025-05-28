using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.Models;

public class Order
{
    public int Id { get; set; }

    [Required]
    public int HotelId { get; set; }
    public Hotel? Hotel { get; set; }

    [Required]
    public int CustomerId { get; set; }
    public Customer? Customer { get; set; }

    [Required]
    public DateTime ReservationDate { get; set; }

    [Required]
    [Display(Name = "Start Date")]
    public DateTime StartDate { get; set; }

    [Required]
    [Display(Name = "End Date")]
    public DateTime EndDate { get; set; }

    [Required]
    public int NumberOfDays { get; set; }

    [Required]
    public decimal FullPrice { get; set; }
}