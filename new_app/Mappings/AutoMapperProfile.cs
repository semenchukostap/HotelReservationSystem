using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using System;

namespace HotelReservationSystem.Mappings
{
    /// <summary>
    /// AutoMapper profile configuration for mapping between models and DTOs.
    /// Provides mapping definitions for all entity types in the Hotel Reservation System.
    /// </summary>
    public class AutoMapperProfile : Profile
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AutoMapperProfile"/> class.
        /// Configures all entity-to-DTO and DTO-to-entity mappings.
        /// </summary>
        public AutoMapperProfile()
        {
            // Hotel mappings
            CreateMap<Hotel, HotelDto>()
                .ForMember(dest => dest.CountryName, 
                    opt => opt.MapFrom(src => src.Country != null ? src.Country.Name : string.Empty));
            
            CreateMap<HotelDto, Hotel>()
                .ForMember(dest => dest.Country, opt => opt.Ignore());
            
            // Country mappings
            CreateMap<Country, CountryDto>();
            CreateMap<CountryDto, Country>();
            
            // Customer mappings
            CreateMap<Customer, CustomerDto>()
                .ForMember(dest => dest.FullName, 
                    opt => opt.MapFrom(src => $"{src.FirstName} {src.LastName}"));
            CreateMap<CustomerDto, Customer>();
            
            // Order mappings
            CreateMap<Order, OrderDto>()
                .ForMember(dest => dest.CustomerName,
                    opt => opt.MapFrom(src => src.Customer != null 
                        ? $"{src.Customer.FirstName} {src.Customer.LastName}" 
                        : string.Empty))
                .ForMember(dest => dest.HotelName,
                    opt => opt.MapFrom(src => src.Hotel != null 
                        ? src.Hotel.Name 
                        : string.Empty));
                
            CreateMap<NewOrderDto, Order>()
                .ForMember(o => o.DateOrdered, opt => opt.MapFrom(src => DateTime.Now))
                .ForMember(o => o.NumberOfDays, 
                    opt => opt.MapFrom(src => (src.EndDate - src.StartDate).Days))
                .ForMember(o => o.FullPrice, opt => opt.Ignore()); // Will be calculated in controller
                
            CreateMap<OrderDto, Order>()
                .ForMember(dest => dest.Customer, opt => opt.Ignore())
                .ForMember(dest => dest.Hotel, opt => opt.Ignore());
        }
    }
}