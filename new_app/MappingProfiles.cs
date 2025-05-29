using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem
{
    /// <summary>
    /// Defines AutoMapper mappings for the hotel reservation system
    /// </summary>
    public class MappingProfiles : Profile
    {
        public MappingProfiles()
        {
            // Map domain entities to DTOs
            CreateMap<Hotel, HotelDto>();
            CreateMap<Country, CountryDto>();
            
            // Map DTOs to domain entities (bidirectional mapping)
            CreateMap<HotelDto, Hotel>();
            CreateMap<CountryDto, Country>();
        }
    }
}
