using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Services
{
    public interface ICustomerService
    {
        Task<IEnumerable<CustomerDto>> GetAllCustomersAsync();
        Task<CustomerDto?> GetCustomerByIdAsync(int id);
        Task<Customer?> GetCustomerEntityByIdAsync(int id);
        Task CreateCustomerAsync(CustomerDto customerDto);
        Task UpdateCustomerAsync(int id, CustomerDto customerDto);
        Task DeleteCustomerAsync(int id);
    }
}