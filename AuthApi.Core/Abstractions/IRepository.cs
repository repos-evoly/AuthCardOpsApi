using System.Linq.Expressions;

namespace AuthApi.Core.Abstractions
{
  public interface IRepository<T> where T : class
  {
    Task<IList<T>> GetAll(
      Expression<Func<T, bool>> expression = null,
      Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
      List<string> includes = null
    );

    Task<T> GetById(Expression<Func<T, bool>> expression = null, List<string> includes = null);
    Task Create(T entity);
    Task CreateRange(IEnumerable<T> entities);
    void Delete(T entity);
    void DeleteRange(IEnumerable<T> entities);
    void Update(T entity);
  }
}