using System.ComponentModel.DataAnnotations;

namespace new_app.Models;

public class Order
{
    public int Id { get; set; }

    [Required]
    public Customer Customer { get; set; } = null!;
    
    [Required]
    public Hotel Hotel { get; set; } = null!;

    [Required]
    public DateTime DateOrdered { get; set; }

    [Required]
    public DateTime StartDate { get; set; }

    [Required]
    public DateTime EndDate { get; set; }

    public int NumberOfDays { get; set; }

    public double FullPrice { get; set; }
}
