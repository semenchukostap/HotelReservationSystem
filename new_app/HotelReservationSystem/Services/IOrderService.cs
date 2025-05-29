using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Authorization;

namespace HotelReservationSystem.Services
{
    /// <summary>
    /// Service interface for order-related operations in the Hotel Reservation System
    /// </summary>
    public interface IOrderService
    {
        /// <summary>
        /// Gets all orders with their related customer and hotel information
        /// </summary>
        /// <returns>A collection of all orders</returns>
        Task<IEnumerable<Order>> GetAllOrdersAsync();

        /// <summary>
        /// Gets a specific order by its ID
        /// </summary>
        /// <param name="id">The ID of the order to retrieve</param>
        /// <returns>The order if found, otherwise null</returns>
        Task<Order> GetOrderByIdAsync(int id);

        /// <summary>
        /// Creates a new order based on the provided information
        /// </summary>
        /// <param name="newOrderDto">Data transfer object containing the new order details</param>
        /// <returns>The created order</returns>
        Task<Order> CreateOrderAsync(NewOrderDto newOrderDto);

        /// <summary>
        /// Updates an existing order
        /// </summary>
        /// <param name="id">The ID of the order to update</param>
        /// <param name="orderDetails">The updated order information</param>
        /// <returns>True if update was successful, otherwise false</returns>
        Task<bool> UpdateOrderAsync(int id, Order orderDetails);

        /// <summary>
        /// Deletes an order by its ID
        /// </summary>
        /// <param name="id">The ID of the order to delete</param>
        /// <returns>True if deletion was successful, otherwise false</returns>
        Task<bool> DeleteOrderAsync(int id);

        /// <summary>
        /// Calculates the price for a potential order based on the date range and hotel
        /// </summary>
        /// <param name="startDate">The start date of the reservation</param>
        /// <param name="endDate">The end date of the reservation</param>
        /// <param name="hotelId">The ID of the hotel</param>
        /// <returns>A tuple containing the number of days and the full price</returns>
        Task<(int numberOfDays, double fullPrice)> CalculateOrderTotalsAsync(DateTime startDate, DateTime endDate, int hotelId);
    }
}