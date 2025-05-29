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
/// Record to represent paginated result
/// </summary>
/// <typeparam name="T">Type of items in the result</typeparam>
public sealed record PaginatedResult<T>
{
    public IReadOnlyList<T> Items { get; init; } = new List<T>();
    public int TotalCount { get; init; }
    public int PageNumber { get; init; }
    public int TotalPages { get; init; }
}

/// <summary>
/// Interface for hotel management operations
/// </summary>
public interface IHotelService
{
    /// <summary>
    /// Retrieves all hotels with optional filtering and pagination
    /// </summary>
    Task<PaginatedResult<Hotel>> GetAllAsync(
        HotelFilterParameters? filterParams = null,
        PaginationParameters? pageParams = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific hotel by ID
    /// </summary>
    Task<Hotel?> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all countries
    /// </summary>
    Task<IReadOnlyList<Country>> GetCountriesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new hotel
    /// </summary>
    /// <exception cref="ValidationException">Thrown when hotel data is invalid</exception>
    Task<Hotel> CreateAsync(Hotel hotel, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing hotel
    /// </summary>
    /// <exception cref="ValidationException">Thrown when hotel data is invalid</exception>
    Task<bool> UpdateAsync(Hotel hotel, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new country
    /// </summary>
    /// <exception cref="ValidationException">Thrown when country data is invalid</exception>
    Task<Country> CreateCountryAsync(Country country, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing country
    /// </summary>
    /// <exception cref="ValidationException">Thrown when country data is invalid</exception>
    Task<bool> UpdateCountryAsync(Country country, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a hotel exists
    /// </summary>
    Task<bool> HotelExistsAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a specific country by ID
    /// </summary>
    Task<Country?> GetCountryByIdAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a hotel by ID
    /// </summary>
    /// <returns>True if hotel was deleted, false if hotel was not found</returns>
    ValueTask<bool> DeleteAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a country by ID
    /// </summary>
    /// <returns>True if country was deleted, false if country was not found</returns>
    ValueTask<bool> DeleteCountryAsync(int id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a hotel has available rooms for given dates
    /// </summary>
    Task<bool> CheckAvailabilityAsync(int hotelId, DateOnly checkIn, DateOnly checkOut, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates hotel data
    /// </summary>
    /// <exception cref="ValidationException">Thrown when validation fails</exception>
    Task ValidateHotelAsync(Hotel hotel, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates country data
    /// </summary>
    /// <exception cref="ValidationException">Thrown when validation fails</exception>
    Task ValidateCountryAsync(Country country, CancellationToken cancellationToken = default);
}