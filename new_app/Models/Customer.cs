using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models;

public class Customer
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [Required(ErrorMessage = "Name is required")]
    [MaxLength(255, ErrorMessage = "Name cannot exceed 255 characters")]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [MaxLength(255, ErrorMessage = "Email cannot exceed 255 characters")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;

    [Display(Name = "Birth Date")]
    [DataType(DataType.Date)]
    public DateTime? BirthDate { get; set; }

    [Display(Name = "Subscribe to Newsletter")]
    public bool IsSubscribedToNewsletter { get; set; }

    [Required(ErrorMessage = "Phone number is required")]
    [Phone(ErrorMessage = "Invalid phone number format")]
    [MaxLength(20, ErrorMessage = "Phone number cannot exceed 20 characters")]
    public string PhoneNumber { get; set; } = string.Empty;

    [MaxLength(500, ErrorMessage = "Address cannot exceed 500 characters")]
    public string? Address { get; set; }

    [Display(Name = "Registration Date")]
    [DataType(DataType.DateTime)]
    public DateTime RegistrationDate { get; set; } = DateTime.UtcNow;

    [Display(Name = "Loyalty Points")]
    [Range(0, int.MaxValue, ErrorMessage = "Loyalty points must be a positive number")]
    public int LoyaltyPoints { get; set; } = 0;

    [MaxLength(50, ErrorMessage = "Nationality cannot exceed 50 characters")]
    public string? Nationality { get; set; }
}