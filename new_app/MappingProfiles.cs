using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem
{
    /// <summary>
    /// Defines AutoMapper mappings for the hotel reservation system
    /// </summary>
    /// <remarks>
    /// This profile configures the mapping between domain models and DTOs
    /// using AutoMapper's fluent API in a .NET 8 compatible way.
    /// </remarks>
    public class MappingProfiles : Profile
    {
        /// <summary>
        /// Initializes mapping configurations between entities and DTOs
        /// </summary>
        public MappingProfiles()
        {
            // Map domain entities to DTOs with modern configurations
            CreateMap<Hotel, HotelDto>()
                // Example of custom member mapping with modern expression syntax
                .ForMember(dest => dest.Name, opt => opt.MapFrom(src => src.Name.Trim()))
                // Modern approach: Handle circular references with PreserveReferences
                .PreserveReferences();
            
            CreateMap<Country, CountryDto>()
                .PreserveReferences();
            
            // Map DTOs to domain entities (bidirectional mapping)
            // Legacy approach would use explicit ReverseMap() for each mapping
            // Modern approach: Define distinct mappings with specific configurations
            CreateMap<HotelDto, Hotel>()
                // You can add validation or transformation logic during mapping
                .ForMember(dest => dest.Name, opt => opt.Condition(src => !string.IsNullOrEmpty(src.Name)))
                .PreserveReferences();
                
            CreateMap<CountryDto, Country>()
                .PreserveReferences();
            
            // Note: In .NET 8, we can leverage more compile-time safety with source generators
            // which would be an alternative approach to these runtime mappings
        }
    }
}
