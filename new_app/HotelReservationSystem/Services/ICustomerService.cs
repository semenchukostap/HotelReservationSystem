using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;

namespace HotelReservationSystem.Services
{
    /// <summary>
    /// Defines the contract for customer-related operations in the system
    /// </summary>
    public interface ICustomerService
    {
        /// <summary>
        /// Gets all customers asynchronously
        /// </summary>
        /// <returns>A collection of all customers</returns>
        Task<IEnumerable<Customer>> GetAllAsync();

        /// <summary>
        /// Gets a customer by their unique identifier asynchronously
        /// </summary>
        /// <param name="id">The customer's unique identifier</param>
        /// <returns>The customer if found, null otherwise</returns>
        Task<Customer> GetByIdAsync(int id);

        /// <summary>
        /// Creates a new customer in the system asynchronously
        /// </summary>
        /// <param name="customer">The customer data to create</param>
        /// <returns>The created customer with assigned ID</returns>
        Task<Customer> CreateAsync(Customer customer);

        /// <summary>
        /// Updates an existing customer asynchronously
        /// </summary>
        /// <param name="customer">The updated customer data</param>
        /// <returns>True if update was successful, false otherwise</returns>
        Task<bool> UpdateAsync(Customer customer);

        /// <summary>
        /// Deletes a customer by their unique identifier asynchronously
        /// </summary>
        /// <param name="id">The customer's unique identifier</param>
        /// <returns>True if deletion was successful, false otherwise</returns>
        Task<bool> DeleteAsync(int id);

        /// <summary>
        /// Checks if a customer with the specified ID exists asynchronously
        /// </summary>
        /// <param name="id">The customer's unique identifier</param>
        /// <returns>True if the customer exists, false otherwise</returns>
        Task<bool> ExistsAsync(int id);

        /// <summary>
        /// Searches for customers based on a query string asynchronously
        /// </summary>
        /// <param name="query">The search query (typically name or other identifiable information)</param>
        /// <returns>A collection of customers matching the query</returns>
        Task<IEnumerable<Customer>> SearchAsync(string query);

        /// <summary>
        /// Gets a view model for customer form with appropriate drop-down data asynchronously
        /// </summary>
        /// <param name="id">The customer's ID if editing, null if creating new</param>
        /// <returns>A populated customer view model</returns>
        Task<CustomerViewModel> GetCustomerFormViewModelAsync(int? id = null);

        /// <summary>
        /// Validates customer data before saving
        /// </summary>
        /// <param name="customer">The customer to validate</param>
        /// <returns>Tuple containing validation result and error message if any</returns>
        (bool IsValid, string ErrorMessage) ValidateCustomer(Customer customer);
    }
}