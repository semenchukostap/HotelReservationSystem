using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Services.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Country, CountryDto>();
            
            CreateMap<Hotel, HotelDto>()
                .ForMember(dest => dest.CountryName, opt => opt.MapFrom(src => src.Country != null ? src.Country.Name : null));
            
            // DTO to Domain
            CreateMap<CountryDto, Country>();
            CreateMap<HotelDto, Hotel>();
            CreateMap<NewOrderDto, Order>();
        }
    }
}