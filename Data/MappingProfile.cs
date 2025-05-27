using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Create maps for each model and DTO
            CreateMap<Hotel, HotelDto>().ReverseMap();
            CreateMap<Country, CountryDto>().ReverseMap();
            // Add additional mappings here as needed
        }
    }
}