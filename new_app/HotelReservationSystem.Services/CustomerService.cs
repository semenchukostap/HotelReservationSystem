using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;
using HotelReservationSystem.Data;
using Microsoft.EntityFrameworkCore;

namespace HotelReservationSystem.Services
{
    public class CustomerService : ICustomerService
    {
        private readonly ApplicationDbContext _context;
        private readonly IMapper _mapper;

        public CustomerService(ApplicationDbContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

        public async Task<IEnumerable<CustomerDto>> GetAllCustomersAsync()
        {
            var customers = await _context.Customers.ToListAsync();
            return _mapper.Map<IEnumerable<CustomerDto>>(customers);
        }

        public async Task<CustomerDto?> GetCustomerByIdAsync(int id)
        {
            var customer = await _context.Customers.FindAsync(id);
            return customer != null ? _mapper.Map<CustomerDto>(customer) : null;
        }

        public async Task<Customer?> GetCustomerEntityByIdAsync(int id)
        {
            return await _context.Customers.FindAsync(id);
        }

        public async Task CreateCustomerAsync(CustomerDto customerDto)
        {
            var customer = _mapper.Map<Customer>(customerDto);
            _context.Customers.Add(customer);
            await _context.SaveChangesAsync();
            customerDto.Id = customer.Id;
        }

        public async Task UpdateCustomerAsync(int id, CustomerDto customerDto)
        {
            var customerInDb = await _context.Customers.FindAsync(id);
            if (customerInDb == null)
                throw new KeyNotFoundException($"Customer with ID {id} not found.");

            _mapper.Map(customerDto, customerInDb);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteCustomerAsync(int id)
        {
            var customer = await _context.Customers.FindAsync(id);
            if (customer == null)
                throw new KeyNotFoundException($"Customer with ID {id} not found.");
                
            _context.Customers.Remove(customer);
            await _context.SaveChangesAsync();
        }
    }
}