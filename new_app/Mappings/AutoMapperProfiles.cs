using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Mappings
{
    public class AutoMapperProfiles : Profile
    {
        public AutoMapperProfiles()
        {
            CreateMap<Hotel, HotelDto>().ReverseMap();
            CreateMap<Country, CountryDto>();
            // Add other mappings as needed
        }
    }
}