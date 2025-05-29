using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models
{
    public class Order : IValidatableObject
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public Customer Customer { get; set; } = null!;
        
        [Required]
        [ForeignKey("Customer")]
        public int CustomerId { get; set; }
        
        [Required]
        public Hotel Hotel { get; set; } = null!;
        
        [Required]
        [ForeignKey("Hotel")]
        public int HotelId { get; set; }

        [Required]
        [Display(Name = "Order Date")]
        [DataType(DataType.DateTime)]
        public DateTime DateOrdered { get; set; }

        [Required]
        [Display(Name = "Start Date")]
        [DataType(DataType.Date)]
        public DateTime StartDate { get; set; }

        [Required]
        [Display(Name = "End Date")]
        [DataType(DataType.Date)]
        public DateTime EndDate { get; set; }

        [Display(Name = "Number of Days")]
        public int NumberOfDays { get; set; }

        [Column(TypeName = "decimal(18, 2)")]
        [Display(Name = "Total Price")]
        [DataType(DataType.Currency)]
        public decimal FullPrice { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (EndDate < StartDate)
            {
                yield return new ValidationResult(
                    "End Date must be after Start Date", 
                    new[] { nameof(EndDate) });
            }
        }
    }
}