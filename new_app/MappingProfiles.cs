using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem
{
    public class MappingProfiles : Profile
    {
        public MappingProfiles()
        {
            CreateMap<Hotel, HotelDto>();
            CreateMap<Country, CountryDto>();
        }
    }
}