using AuthApi.Core.Extensions;
using FluentValidation;
using Microsoft.AspNetCore.Http;

namespace AuthApi.Core.Filters;

public class ValidationFilter<T> : IEndpointFilter where T : class
{
  private readonly IValidator<T> _validator;

  public ValidationFilter(IValidator<T> validator)
  {
    _validator = validator;
  }
 async ValueTask<object> IEndpointFilter.InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
  {
    var arg = context.Arguments.SingleOrDefault(a => a.GetType() == typeof(T)) as T;
    if (arg is null) return Results.BadRequest("The argument is invalid");

    var result = await _validator.ValidateAsync((T)arg);
    if (!result.IsValid)
    {
      var errors = result.Errors.GetErrors();
      return Results.Problem(errors);
    }
    return await next(context);
  }
}