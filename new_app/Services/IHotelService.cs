using System.ComponentModel.DataAnnotations;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Services;

/// <summary>
/// Record to define hotel filtering parameters
/// </summary>
public sealed record HotelFilterParameters
{
    public string? Name { get; init; }
    public string? CountryName { get; init; }
    public decimal? MinPrice { get; init; }
    public decimal? MaxPrice { get; init; }
    public int? MinRating { get; init; }
    public bool? IsActive { get; init; }
}

/// <summary>
/// Record to define pagination parameters
/// </summary>
public sealed record PaginationParameters
{
    [Range(1, int.MaxValue)]
    public int PageNumber { get; init; } = 1;

    [Range(1, 100)]
    public int PageSize { get; init; } = 10;
}

/// <summary>
/// Record to represent operation result with data and status
/// </summary>
/// <typeparam name="T">Type of the result data</typeparam>
public sealed record OperationResult<T>
{
    public bool Success { get; init; }
    public T? Data { get; init; }
    public string? Message { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = new List<string>();
}

/// <summary>
/// Record to represent paginated result
/// </summary>
/// <typeparam name="T">Type of items in the result</typeparam>
public sealed record PaginatedResult<T>
{
    public IReadOnlyList<T> Items { get; init; } = new List<T>();
    public int TotalCount { get; init; }
    public int PageNumber { get; init; }
    public int TotalPages { get; init; }
    public bool HasPrevious => PageNumber > 1;
    public bool HasNext => PageNumber < TotalPages;
}

/// <summary>
/// Interface for hotel management operations
/// </summary>
public interface IHotelService
{
    /// <summary>
    /// Retrieves all hotels with optional filtering and pagination
    /// </summary>
    /// <param name="filterParams">Optional filtering parameters</param>
    /// <param name="pageParams">Optional pagination parameters</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Paginated result of hotels</returns>
    Task<OperationResult<PaginatedResult<Hotel>>> GetAllAsync(
        HotelFilterParameters? filterParams = null,
        PaginationParameters? pageParams = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific hotel by ID
    /// </summary>
    /// <param name="id">Hotel ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result containing the hotel if found</returns>
    Task<OperationResult<Hotel>> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all countries
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result containing list of countries</returns>
    Task<OperationResult<IReadOnlyList<Country>>> GetCountriesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new hotel
    /// </summary>
    /// <param name="hotel">Hotel data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result containing the created hotel</returns>
    Task<OperationResult<Hotel>> CreateAsync(Hotel hotel, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing hotel
    /// </summary>
    /// <param name="hotel">Updated hotel data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating success or failure</returns>
    Task<OperationResult<bool>> UpdateAsync(Hotel hotel, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new country
    /// </summary>
    /// <param name="country">Country data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result containing the created country</returns>
    Task<OperationResult<Country>> CreateCountryAsync(Country country, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing country
    /// </summary>
    /// <param name="country">Updated country data</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating success or failure</returns>
    Task<OperationResult<bool>> UpdateCountryAsync(Country country, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a hotel exists
    /// </summary>
    /// <param name="id">Hotel ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating if hotel exists</returns>
    Task<OperationResult<bool>> HotelExistsAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific country by ID
    /// </summary>
    /// <param name="id">Country ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result containing the country if found</returns>
    Task<OperationResult<Country>> GetCountryByIdAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a hotel by ID
    /// </summary>
    /// <param name="id">Hotel ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating success or failure</returns>
    Task<OperationResult<bool>> DeleteAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a country by ID
    /// </summary>
    /// <param name="id">Country ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating success or failure</returns>
    Task<OperationResult<bool>> DeleteCountryAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a hotel has available rooms for given dates
    /// </summary>
    /// <param name="hotelId">Hotel ID</param>
    /// <param name="checkIn">Check-in date</param>
    /// <param name="checkOut">Check-out date</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating room availability</returns>
    Task<OperationResult<bool>> CheckAvailabilityAsync(int hotelId, DateOnly checkIn, DateOnly checkOut, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates hotel data
    /// </summary>
    /// <param name="hotel">Hotel data to validate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating validation success or failures</returns>
    Task<OperationResult<bool>> ValidateHotelAsync(Hotel hotel, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates country data
    /// </summary>
    /// <param name="country">Country data to validate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation result indicating validation success or failures</returns>
    Task<OperationResult<bool>> ValidateCountryAsync(Country country, CancellationToken cancellationToken = default);
}