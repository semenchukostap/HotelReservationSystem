using HotelReservationSystem.Core.DTOs;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace HotelReservationSystem.Core.Services;

public interface IOrderService
{
    Task<IEnumerable<OrderDto>> GetAllOrdersAsync();
    Task<OrderDto?> GetOrderByIdAsync(int id);
    Task<int> CreateOrderAsync(NewOrderDto orderDto);
    Task DeleteOrderAsync(int id);
}