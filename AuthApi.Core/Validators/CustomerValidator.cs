using AuthApi.Core.Dtos;
using FluentValidation;

namespace AuthApi.Validators
{
    public class CustomerValidator : AbstractValidator<EditCustomerDto>
    {
        public CustomerValidator()
        {
            // UserId is required
            RuleFor(c => c.UserId)
                .GreaterThan(0)
                .WithMessage("UserId must be greater than 0.");

            // CustomerId must be at most 8 characters (if provided)
            RuleFor(c => c.CustomerId)
                .MaximumLength(8)
                .WithMessage("CustomerId must not exceed 8 characters.");

            // NationalId validation (if provided)
            RuleFor(c => c.NationalId)
                .MaximumLength(25)
                .WithMessage("NationalId must not exceed 25 characters.");

            // BirthDate should not be in the future
            RuleFor(c => c.BirthDate)
                .LessThanOrEqualTo(DateTime.UtcNow)
                .WithMessage("BirthDate cannot be in the future.");

            // Address validation (if provided)
            RuleFor(c => c.Address)
                .MaximumLength(225)
                .WithMessage("Address must not exceed 225 characters.");

            // Phone validation (if provided)
            RuleFor(c => c.Phone)
                .Matches(@"^\+?\d{7,15}$") // Ensures valid international phone numbers
                .When(c => !string.IsNullOrEmpty(c.Phone))
                .WithMessage("Phone number is not valid.");

            // KYC Status must be provided
            RuleFor(c => c.KycStatus)
                .NotEmpty()
                .WithMessage("KycStatus is required.");
        }
    }
}
