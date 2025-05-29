using HotelReservationSystem.Data;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using AutoMapper.QueryableExtensions;

namespace HotelReservationSystem.Services
{
    /// <summary>
    /// Implementation of ICustomerService interface that handles customer-related business logic for .NET 8
    /// </summary>
    public class CustomerService : ICustomerService
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;

        public CustomerService(ApplicationDbContext context, IMapper mapper)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        }

        /// <summary>
        /// Gets all customers asynchronously
        /// </summary>
        /// <returns>A collection of CustomerDto objects</returns>
        public async Task<IEnumerable<CustomerDto>> GetAllAsync()
        {
            return await _context.Customers
                .AsNoTracking()
                .ProjectTo<CustomerDto>(_mapper.ConfigurationProvider)
                .ToListAsync();
        }

        /// <summary>
        /// Gets a customer by ID asynchronously
        /// </summary>
        /// <param name="id">The customer ID</param>
        /// <returns>A CustomerDto object if found, null otherwise</returns>
        public async Task<CustomerDto?> GetByIdAsync(int id)
        {
            var customer = await _context.Customers
                .AsNoTracking()
                .SingleOrDefaultAsync(c => c.Id == id);

            return customer != null ? _mapper.Map<CustomerDto>(customer) : null;
        }

        /// <summary>
        /// Creates a new customer asynchronously
        /// </summary>
        /// <param name="customerDto">The customer data to create</param>
        /// <returns>The created CustomerDto with ID</returns>
        public async Task<CustomerDto> CreateAsync(CustomerDto customerDto)
        {
            if (customerDto == null)
                throw new ArgumentNullException(nameof(customerDto));

            var customer = _mapper.Map<Customer>(customerDto);
            
            await _context.Customers.AddAsync(customer);
            await _context.SaveChangesAsync();

            return _mapper.Map<CustomerDto>(customer);
        }

        /// <summary>
        /// Updates an existing customer asynchronously
        /// </summary>
        /// <param name="id">The customer ID to update</param>
        /// <param name="customerDto">The updated customer data</param>
        /// <returns>True if updated successfully, false otherwise</returns>
        public async Task<bool> UpdateAsync(int id, CustomerDto customerDto)
        {
            if (customerDto == null)
                throw new ArgumentNullException(nameof(customerDto));

            var customerInDb = await _context.Customers
                .SingleOrDefaultAsync(c => c.Id == id);

            if (customerInDb == null)
                return false;

            // Only update the fields that should be updated
            customerInDb.Name = customerDto.Name;
            customerInDb.Birthdate = customerDto.Birthdate;

            await _context.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// Deletes a customer asynchronously
        /// </summary>
        /// <param name="id">The customer ID to delete</param>
        /// <returns>True if deleted successfully, false otherwise</returns>
        public async Task<bool> DeleteAsync(int id)
        {
            var customer = await _context.Customers
                .SingleOrDefaultAsync(c => c.Id == id);

            if (customer == null)
                return false;

            // Check if customer has any orders before deletion
            var hasOrders = await _context.Orders
                .AnyAsync(o => o.CustomerId == id);

            if (hasOrders)
                throw new InvalidOperationException("Cannot delete customer with existing orders");

            _context.Customers.Remove(customer);
            await _context.SaveChangesAsync();
            
            return true;
        }

        /// <summary>
        /// Checks if a customer with the specified ID exists
        /// </summary>
        /// <param name="id">The customer ID</param>
        /// <returns>True if exists, false otherwise</returns>
        public async Task<bool> ExistsAsync(int id)
        {
            return await _context.Customers.AnyAsync(c => c.Id == id);
        }

        /// <summary>
        /// Searches for customers by name pattern asynchronously
        /// </summary>
        /// <param name="searchTerm">The search term to look for in customer names</param>
        /// <returns>A collection of matching CustomerDto objects</returns>
        public async Task<IEnumerable<CustomerDto>> SearchByNameAsync(string searchTerm)
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
                return await GetAllAsync();

            return await _context.Customers
                .AsNoTracking()
                .Where(c => c.Name.Contains(searchTerm))
                .ProjectTo<CustomerDto>(_mapper.ConfigurationProvider)
                .ToListAsync();
        }
    }
}
