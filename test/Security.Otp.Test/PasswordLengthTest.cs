using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Security.Otp.Test
{
    public class PasswordLengthTest
    {
        [Theory]
        [InlineData(0, 1, "D0")]
        [InlineData(1, 10, "D1")]
        [InlineData(2, 100, "D2")]
        [InlineData(3, 1000, "D3")]
        [InlineData(4, 10000, "D4")]
        [InlineData(5, 100000, "D5")]
        [InlineData(6, 1000000, "D6")]
        [InlineData(7, 10000000, "D7")]
        [InlineData(8, 100000000, "D8")]
        public void APasswordLength_WithTheCorrectMetadata_IsCreated(int digits, int power, string format)
        {
            // Act
            var result = PasswordLength.Of(digits);

            // Assert
            Assert.Equal(digits, result.Digits);
            Assert.Equal(format, result.Format);
            Assert.Equal(power, result.Power);
        }

        [Theory]
        [InlineData(-1)]
        [InlineData(9)]
        public void APasswordLength_OfAnInvalidLegnth_ThrowsException(int digits)
        {
            // Act & Assert
            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => PasswordLength.Of(digits));

            Assert.Equal("digits", exception.ParamName);
            Assert.Equal($"A password of {digits} in length cannot be created. Only passwords with a length between 0 and 8 (inclusive) are supported.\r\nParameter name: digits", exception.Message);
        }
    }
}
