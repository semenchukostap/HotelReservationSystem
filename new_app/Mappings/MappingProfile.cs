using AutoMapper;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;

namespace HotelReservationSystem.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Hotel, HotelDto>()
                .ForMember(dest => dest.CountryName,
                    opt => opt.MapFrom(src => src.Country.Name));
                
            CreateMap<HotelDto, Hotel>();
            CreateMap<Country, CountryDto>();
            CreateMap<Order, OrderDto>()
                .ForMember(dest => dest.CustomerName,
                    opt => opt.MapFrom(src => src.Customer.UserName))
                .ForMember(dest => dest.HotelName,
                    opt => opt.MapFrom(src => src.Hotel.Name));
        }
    }
}