using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Mappings
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            // Hotel mappings
            CreateMap<Hotel, HotelDto>()
                .ForMember(dest => dest.CountryName, 
                    opt => opt.MapFrom(src => src.Country != null ? src.Country.Name : string.Empty));
            
            CreateMap<HotelDto, Hotel>();
            
            // Country mappings
            CreateMap<Country, CountryDto>();
            CreateMap<CountryDto, Country>();
            
            // Order mappings
            CreateMap<NewOrderDto, Order>()
                .ForMember(o => o.DateOrdered, opt => opt.MapFrom(src => DateTime.Now));
        }
    }
}