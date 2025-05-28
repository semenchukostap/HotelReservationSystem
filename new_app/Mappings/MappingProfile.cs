using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using HotelReservationSystem.ViewModels;

namespace HotelReservationSystem.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Hotel, HotelDto>()
                .ForMember(dest => dest.CountryName, opt => opt.MapFrom(src => src.Country != null ? src.Country.Name : null));
            CreateMap<Country, CountryDto>();
            CreateMap<Customer, CustomerViewModel>();

            // DTO to Domain
            CreateMap<HotelDto, Hotel>();
            CreateMap<CountryDto, Country>();
            CreateMap<CustomerViewModel, Customer>();

            // ViewModels
            CreateMap<Hotel, HotelViewModel>();
            CreateMap<HotelViewModel, Hotel>();
        }
    }
}