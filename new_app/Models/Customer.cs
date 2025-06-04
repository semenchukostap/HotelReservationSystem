using System.ComponentModel.DataAnnotations;

namespace new_app.Models;

public class Customer
{
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    public DateTime? Birthdate { get; set; }
}