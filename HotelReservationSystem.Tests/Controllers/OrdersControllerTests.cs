using NUnit.Framework;
using Moq;
using HotelReservationSystem.Controllers;
using HotelReservationSystem.Models;
using System.Web.Mvc;

namespace HotelReservationSystem.Tests.Controllers
{
    [TestFixture]
    public class OrdersControllerTests
    {
        private OrdersController _controller;

        [SetUp]
        public void SetUp()
        {
            _controller = new OrdersController();
        }

        [Test]
        public void Index_WhenCalled_ReturnsViewResult()
        {
            var result = _controller.Index() as ViewResult;

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public void New_WhenCalled_ReturnsViewResult()
        {
            var result = _controller.New() as ViewResult;

            Assert.That(result, Is.Not.Null);
        }

        [Test]
        public void Details_WhenCalledWithId_ReturnsViewResult()
        {
            var result = _controller.Details(1) as ViewResult;

            Assert.That(result, Is.Not.Null);
        }
    }
}
