using System;

namespace HotelReservationSystem.DTOs
{
    /// <summary>
    /// Parameters for searching and filtering orders
    /// </summary>
    public class OrderSearchParams
    {
        /// <summary>
        /// Filter by customer ID
        /// </summary>
        public int? CustomerId { get; set; }
        
        /// <summary>
        /// Filter by hotel ID
        /// </summary>
        public int? HotelId { get; set; }
        
        /// <summary>
        /// Filter for orders with start date after this date
        /// </summary>
        public DateTime? FromDate { get; set; }
        
        /// <summary>
        /// Filter for orders with end date before this date
        /// </summary>
        public DateTime? ToDate { get; set; }
        
        /// <summary>
        /// Filter for orders with price greater than or equal to this value
        /// </summary>
        public double? MinPrice { get; set; }
        
        /// <summary>
        /// Filter for orders with price less than or equal to this value
        /// </summary>
        public double? MaxPrice { get; set; }
        
        /// <summary>
        /// Field to sort results by (date, price, customer, hotel)
        /// </summary>
        public string? SortBy { get; set; }
        
        /// <summary>
        /// Sort direction (asc or desc)
        /// </summary>
        public string? SortDirection { get; set; }
        
        /// <summary>
        /// Page number for pagination (1-based)
        /// </summary>
        public int? PageNumber { get; set; }
        
        /// <summary>
        /// Page size for pagination
        /// </summary>
        public int? PageSize { get; set; }
    }
}