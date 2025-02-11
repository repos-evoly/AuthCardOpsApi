using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Core.Dtos
{
    public class EditCustomerDto
    {
        [Required]
        public int UserId { get; set; } // Ensures the customer is linked to a valid user.

        [MaxLength(8)]
        public string CustomerId { get; set; } // Cannot be changed after creation.

        [MaxLength(25)]
        public string NationalId { get; set; } // Allows updating the national ID.

        public DateTime? BirthDate { get; set; }

        [MaxLength(225)]
        public string Address { get; set; }

        [MaxLength(225)]
        public string Phone { get; set; }

        [Required]
        public string KycStatus { get; set; } = "Pending"; // Mandatory for compliance.
    }
}
