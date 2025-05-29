using System.ComponentModel.DataAnnotations;
using AutoMapper;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.ViewModels;

/// <summary>
/// View model representing hotel details and associated data for the UI layer
/// </summary>
public class HotelViewModel : IValidatableObject
{
    /// <summary>
    /// Gets or sets the unique identifier for the hotel
    /// </summary>
    [Required(ErrorMessage = "Hotel ID is required")]
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the name of the hotel
    /// </summary>
    [Required(ErrorMessage = "Hotel name is required")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "Hotel name must be between 2 and 100 characters")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the description of the hotel
    /// </summary>
    [Required(ErrorMessage = "Hotel description is required")]
    [StringLength(500, ErrorMessage = "Description cannot exceed 500 characters")]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the star rating of the hotel
    /// </summary>
    [Required(ErrorMessage = "Star rating is required")]
    [Range(1, 5, ErrorMessage = "Star rating must be between 1 and 5")]
    public int StarRating { get; set; }

    /// <summary>
    /// Gets or sets the address of the hotel
    /// </summary>
    [Required(ErrorMessage = "Address is required")]
    [StringLength(200, ErrorMessage = "Address cannot exceed 200 characters")]
    public string Address { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the country ID where the hotel is located
    /// </summary>
    [Required(ErrorMessage = "Country is required")]
    public int CountryId { get; set; }

    /// <summary>
    /// Gets or sets the country details
    /// </summary>
    public CountryViewModel? Country { get; set; }

    /// <summary>
    /// Gets or sets the list of available countries for selection
    /// </summary>
    public IEnumerable<CountryViewModel> Countries { get; set; } = Enumerable.Empty<CountryViewModel>();

    /// <summary>
    /// Implements custom validation logic for the hotel view model
    /// </summary>
    /// <param name="validationContext">Validation context</param>
    /// <returns>Collection of validation results</returns>
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (StarRating == 5 && string.IsNullOrWhiteSpace(Description))
        {
            yield return new ValidationResult(
                "Description is required for 5-star hotels",
                new[] { nameof(Description) }
            );
        }

        if (Name.Length < 2)
        {
            yield return new ValidationResult(
                "Hotel name must be at least 2 characters long",
                new[] { nameof(Name) }
            );
        }
    }
}

/// <summary>
/// AutoMapper profile for hotel-related mappings
/// </summary>
public class HotelMappingProfile : Profile
{
    public HotelMappingProfile()
    {
        CreateMap<Hotel, HotelViewModel>()
            .ForMember(dest => dest.CountryId, opt => opt.MapFrom(src => src.CountryId))
            .ForMember(dest => dest.Country, opt => opt.MapFrom(src => src.Country))
            .ReverseMap();

        CreateMap<Country, CountryViewModel>().ReverseMap();
    }
}