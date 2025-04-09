using FluentValidation.Results;

namespace AuthCardOpsApi.Core.Extensions;

public static class ValidationErrorExtensions
{
  public static string GetErrors(this List<ValidationFailure> errors)
  {
    var errorMessages = "";
    errors.ForEach(e => errorMessages += e.ErrorMessage + " ");
    return errorMessages;
  }
}