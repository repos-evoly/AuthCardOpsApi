using System;

namespace AuthApi.Core.Dtos
{
    public class CustomerDto
    {
        public string CustomerId { get; set; }
        public int UserId { get; set; }
        public string NationalId { get; set; }
        public DateTime? BirthDate { get; set; }
        public string Address { get; set; }
        public string Phone { get; set; }
        public string KycStatus { get; set; }
    }
}
