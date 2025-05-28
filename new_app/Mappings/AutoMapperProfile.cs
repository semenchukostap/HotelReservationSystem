using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using System;

namespace HotelReservationSystem.Mappings
{
    /// <summary>
    /// AutoMapper profile configuration for mapping between models and DTOs.
    /// This replaces the legacy MappingProfile.cs from App_Start folder.
    /// </summary>
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
                .ForMember(o => o.DateOrdered, opt => opt.MapFrom(src => DateTime.Now))
                .ForMember(o => o.NumberOfDays, 
                    opt => opt.MapFrom(src => (src.EndDate - src.StartDate).Days))
                .ForMember(o => o.FullPrice, opt => opt.Ignore()); // Will be calculated in controller
        }
    }
}