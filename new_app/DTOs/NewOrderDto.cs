using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.DTOs;

/// <summary>
/// Data Transfer Object for creating a new hotel reservation order
/// </summary>
public sealed class NewOrderDto
{
    /// <summary>
    /// The ID of the customer making the reservation
    /// </summary>
    [Required(ErrorMessage = "Customer ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Customer ID must be greater than 0")]
    public int CustomerId { get; set; }

    /// <summary>
    /// The ID of the hotel being reserved
    /// </summary>
    [Required(ErrorMessage = "Hotel ID is required")]
    [Range(1, int.MaxValue, ErrorMessage = "Hotel ID must be greater than 0")]
    public int HotelId { get; set; }

    /// <summary>
    /// The start date of the reservation
    /// </summary>
    [Required(ErrorMessage = "Start date is required")]
    [DataType(DataType.Date)]
    public DateTime StartDate { get; set; }

    /// <summary>
    /// The end date of the reservation
    /// </summary>
    [Required(ErrorMessage = "End date is required")]
    [DataType(DataType.Date)]
    public DateTime EndDate { get; set; }

    /// <summary>
    /// The total number of days for the reservation.
    /// This is calculated from StartDate and EndDate.
    /// </summary>
    [Range(1, 365, ErrorMessage = "Reservation duration must be between 1 and 365 days")]
    public int NumberOfDays { get; set; }
    
    /// <summary>
    /// Additional notes or special requests for the reservation
    /// </summary>
    [StringLength(500, ErrorMessage = "Notes cannot exceed 500 characters")]
    public string? Notes { get; set; }
}
