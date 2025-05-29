using System.ComponentModel;
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
    [Display(Name = "Hotel ID")]
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the name of the hotel
    /// </summary>
    [Required(ErrorMessage = "Hotel name is required")]
    [Display(Name = "Hotel Name")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "Hotel name must be between {2} and {1} characters")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the description of the hotel
    /// </summary>
    [Required(ErrorMessage = "Hotel description is required")]
    [Display(Name = "Description")]
    [DataType(DataType.MultilineText)]
    [StringLength(500, ErrorMessage = "Description cannot exceed {1} characters")]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the star rating of the hotel
    /// </summary>
    [Required(ErrorMessage = "Star rating is required")]
    [Display(Name = "Star Rating")]
    [Range(1, 5, ErrorMessage = "Star rating must be between {1} and {2}")]
    public int StarRating { get; set; }

    /// <summary>
    /// Gets or sets the address of the hotel
    /// </summary>
    [Required(ErrorMessage = "Address is required")]
    [Display(Name = "Hotel Address")]
    [DataType(DataType.MultilineText)]
    [StringLength(200, ErrorMessage = "Address cannot exceed {1} characters")]
    public string Address { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets whether the hotel is all-inclusive
    /// </summary>
    [Display(Name = "All-Inclusive")]
    public bool IsAllInclusive { get; set; }

    /// <summary>
    /// Gets or sets the base price per night
    /// </summary>
    [Required(ErrorMessage = "Base price is required")]
    [Display(Name = "Base Price per Night")]
    [DataType(DataType.Currency)]
    [Range(0.01, 99999.99, ErrorMessage = "Price must be between {1} and {2}")]
    public decimal BasePrice { get; set; }

    /// <summary>
    /// Gets or sets the country ID where the hotel is located
    /// </summary>
    [Required(ErrorMessage = "Country is required")]
    [Display(Name = "Country")]
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
    /// Gets the formatted display name including star rating
    /// </summary>
    [Display(Name = "Hotel")]
    public string DisplayName => $"{Name} ({StarRating}★)";

    /// <summary>
    /// Gets the formatted price with currency
    /// </summary>
    public string FormattedPrice => BasePrice.ToString("C");

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

        if (StarRating == 5 && !IsAllInclusive)
        {
            yield return new ValidationResult(
                "5-star hotels must offer all-inclusive packages",
                new[] { nameof(IsAllInclusive) }
            );
        }

        if (IsAllInclusive && BasePrice < 100)
        {
            yield return new ValidationResult(
                "All-inclusive packages must have a minimum base price of $100",
                new[] { nameof(BasePrice) }
            );
        }
    }
}

/// <summary>
/// View model representing country details
/// </summary>
public class CountryViewModel
{
    public int Id { get; set; }

    [Required(ErrorMessage = "Country name is required")]
    [Display(Name = "Country Name")]
    public string Name { get; set; } = string.Empty;

    [Display(Name = "Country Code")]
    [StringLength(2, MinimumLength = 2, ErrorMessage = "Country code must be 2 characters")]
    public string Code { get; set; } = string.Empty;
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
            .ForMember(dest => dest.DisplayName, opt => opt.Ignore())
            .ForMember(dest => dest.FormattedPrice, opt => opt.Ignore())
            .ForMember(dest => dest.Countries, opt => opt.Ignore())
            .ReverseMap()
            .ForMember(dest => dest.Country, opt => opt.Ignore());

        CreateMap<Country, CountryViewModel>()
            .ReverseMap();
    }
}