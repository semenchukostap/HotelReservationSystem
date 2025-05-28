using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Represents a hotel reservation order in the system.
    /// </summary>
    public sealed class Order
    {
        /// <summary>
        /// Gets or sets the unique identifier for the order.
        /// </summary>
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        /// <summary>
        /// Gets or sets the customer who placed the order.
        /// </summary>
        [Required(ErrorMessage = "Customer information is required")]
        public required Customer Customer { get; set; }
        
        /// <summary>
        /// Gets or sets the hotel associated with this reservation.
        /// </summary>
        [Required(ErrorMessage = "Hotel information is required")]
        public required Hotel Hotel { get; set; }

        /// <summary>
        /// Gets or sets the date and time when the order was placed.
        /// </summary>
        [Required(ErrorMessage = "Order date is required")]
        [DataType(DataType.DateTime)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd HH:mm}", ApplyFormatInEditMode = true)]
        public DateTime DateOrdered { get; init; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets the start date of the reservation.
        /// </summary>
        [Required(ErrorMessage = "Start date is required")]
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        public required DateTime StartDate { get; set; }

        /// <summary>
        /// Gets or sets the end date of the reservation.
        /// </summary>
        [Required(ErrorMessage = "End date is required")]
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        [DateGreaterThan("StartDate", ErrorMessage = "End date must be after start date")]
        public required DateTime EndDate { get; set; }

        /// <summary>
        /// Gets the total number of days for the reservation.
        /// This is calculated from the StartDate and EndDate.
        /// </summary>
        [Range(1, int.MaxValue, ErrorMessage = "Number of days must be at least 1")]
        public int NumberOfDays => (EndDate - StartDate).Days + 1;

        /// <summary>
        /// Gets or sets the full price of the reservation.
        /// </summary>
        [Range(0, double.MaxValue, ErrorMessage = "Price cannot be negative")]
        [DataType(DataType.Currency)]
        [Column(TypeName = "decimal(18, 2)")]
        [Precision(18, 2)]
        public decimal FullPrice { get; set; }
    }

    /// <summary>
    /// Custom validation attribute to ensure one date is greater than another date property
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    public sealed class DateGreaterThanAttribute : ValidationAttribute
    {
        private readonly string _comparisonProperty;

        public DateGreaterThanAttribute(string comparisonProperty)
        {
            _comparisonProperty = comparisonProperty;
        }

        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value is null)
                return ValidationResult.Success;

            var currentValue = (DateTime)value;
            
            var property = validationContext.ObjectType.GetProperty(_comparisonProperty);
            if (property == null)
                return new ValidationResult($"Unknown property: {_comparisonProperty}");
                
            var comparisonValue = (DateTime)property.GetValue(validationContext.ObjectInstance)!;

            return currentValue > comparisonValue 
                ? ValidationResult.Success 
                : new ValidationResult(ErrorMessage);
        }
    }
}