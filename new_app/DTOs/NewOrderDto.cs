namespace new_app.DTOs;

using System;
using System.ComponentModel.DataAnnotations;

public class NewOrderDto
{
    [Required(ErrorMessage = "Customer ID is required")]
    public required int CustomerId { get; set; }

    [Required(ErrorMessage = "Hotel ID is required")]
    public required int HotelId { get; set; }

    [Required(ErrorMessage = "Start date is required")]
    public required DateOnly StartDate { get; set; }

    [Required(ErrorMessage = "End date is required")]
    public required DateOnly EndDate { get; set; }
}
