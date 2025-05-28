using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Core.Models;

public class Customer
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [MaxLength(255)]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public DateTime BirthDate { get; set; }

    public bool IsSubscribedToNewsletter { get; set; }

    // Navigation property for orders
    public ICollection<Order>? Orders { get; set; }
}