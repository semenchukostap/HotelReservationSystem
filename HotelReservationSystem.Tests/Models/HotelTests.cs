using NUnit.Framework;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Tests.Models
{
    [TestFixture]
    public class HotelTests
    {
        [Test]
        public void Hotel_Properties_ShouldHaveRequiredAttributes()
        {
            // Arrange
            var hotel = new Hotel();

            // Act
            var properties = hotel.GetType().GetProperties();

            // Assert
            foreach (var property in properties)
            {
                var requiredAttribute = property.GetCustomAttributes(typeof(RequiredAttribute), false).FirstOrDefault();
                if (requiredAttribute != null)
                {
                    Assert.IsNotNull(requiredAttribute, $"{property.Name} should have Required attribute.");
                }
            }
        }

        [Test]
        public void Hotel_Stars_ShouldBeWithinRange()
        {
            // Arrange
            var hotel = new Hotel { Stars = 6 };

            // Act & Assert
            var validationContext = new ValidationContext(hotel, null, null);
            var validationResults = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(hotel, validationContext, validationResults, true);

            Assert.IsFalse(isValid, "Stars should be between 1 and 5.");
        }

        [Test]
        public void Hotel_PricePerNight_ShouldBeWithinRange()
        {
            // Arrange
            var hotel = new Hotel { PricePerNight = 1001 };

            // Act & Assert
            var validationContext = new ValidationContext(hotel, null, null);
            var validationResults = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(hotel, validationContext, validationResults, true);

            Assert.IsFalse(isValid, "PricePerNight should be between 1 and 1000.");
        }
    }
}