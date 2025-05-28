using HotelReservationSystem.Core.DTOs;

namespace HotelReservationSystem.Services
{
    public interface IOrderService
    {
        Task<IEnumerable<OrderDto>> GetAllOrdersAsync();
        Task<OrderDto?> GetOrderByIdAsync(int id);
        Task CreateOrderAsync(OrderDto orderDto);
        Task DeleteOrderAsync(int id);
    }
}