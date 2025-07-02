using NUnit.Framework;
using HotelReservationSystem.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace HotelReservationSystem.Tests.Models
{
    [TestFixture]
    public class OrderTests
    {
        [Test]
        public void Order_WhenPropertiesAreSet_ShouldBeValid()
        {
            var customer = new Customer { Id = 1, Name = "John Doe" };
            var hotel = new Hotel { Id = 1, Name = "Hotel ABC" };
            var order = new Order
            {
                Id = 1,
                Customer = customer,
                Hotel = hotel,
                DateOrdered = DateTime.Now,
                StartDate = DateTime.Now.AddDays(1),
                EndDate = DateTime.Now.AddDays(5),
                NumberOfDays = 4,
                FullPrice = 400.0
            };

            Assert.That(order.Customer, Is.EqualTo(customer));
            Assert.That(order.Hotel, Is.EqualTo(hotel));
            Assert.That(order.DateOrdered, Is.Not.Null);
            Assert.That(order.StartDate, Is.GreaterThan(order.DateOrdered));
            Assert.That(order.EndDate, Is.GreaterThan(order.StartDate));
            Assert.That(order.NumberOfDays, Is.EqualTo(4));
            Assert.That(order.FullPrice, Is.EqualTo(400.0));
        }

        [Test]
        public void Order_WhenMissingRequiredProperties_ShouldBeInvalid()
        {
            var order = new Order();

            var context = new ValidationContext(order, null, null);
            var results = new List<ValidationResult>();

            var isValid = Validator.TryValidateObject(order, context, results, true);

            Assert.That(isValid, Is.False);
            Assert.That(results.Count, Is.GreaterThan(0));
        }
    }
}
