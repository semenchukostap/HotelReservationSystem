using System;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.ViewModels
{
    /// <summary>
    /// View model for customer form operations
    /// </summary>
    public class CustomerViewModel
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Customer name is required")]
        [MaxLength(255, ErrorMessage = "Name cannot exceed 255 characters")]
        [Display(Name = "Customer Name")]
        public string Name { get; set; } = string.Empty;

        [Display(Name = "Date of Birth")]
        [DisplayFormat(DataFormatString = "{0:d MMM yyyy}", ApplyFormatInEditMode = true)]
        public DateTime? Birthdate { get; set; }

        /// <summary>
        /// Default constructor for creating a new customer
        /// </summary>
        public CustomerViewModel()
        {
            // Empty constructor for new customer form operations
        }

        /// <summary>
        /// Constructor that maps from Customer model to CustomerViewModel
        /// </summary>
        /// <param name="customer">Customer entity from database</param>
        public CustomerViewModel(Models.Customer customer)
        {
            if (customer == null)
                throw new ArgumentNullException(nameof(customer));

            Id = customer.Id;
            Name = customer.Name;
            Birthdate = customer.Birthdate;
        }

        /// <summary>
        /// Maps the view model back to a Customer entity
        /// </summary>
        /// <returns>Customer entity mapped from this view model</returns>
        public Models.Customer ToCustomerEntity()
        {
            return new Models.Customer
            {
                Id = this.Id,
                Name = this.Name,
                Birthdate = this.Birthdate
            };
        }
    }
}