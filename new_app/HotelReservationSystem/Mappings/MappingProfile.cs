using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Hotel, HotelDto>();
            CreateMap<Country, CountryDto>();
            
            // DTO to Domain
            CreateMap<HotelDto, Hotel>();
            CreateMap<CountryDto, Country>();
            CreateMap<NewOrderDto, Order>();
        }
    }
}