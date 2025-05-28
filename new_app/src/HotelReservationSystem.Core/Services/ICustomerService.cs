using HotelReservationSystem.Core.DTOs;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Core.Services;

public interface ICustomerService
{
    Task<IEnumerable<CustomerDto>> GetAllCustomersAsync();
    Task<CustomerDto?> GetCustomerByIdAsync(int id);
    Task<int> CreateCustomerAsync(CustomerDto customerDto);
    Task UpdateCustomerAsync(int id, CustomerDto customerDto);
    Task DeleteCustomerAsync(int id);
}