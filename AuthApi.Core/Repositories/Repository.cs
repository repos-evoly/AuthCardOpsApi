using System.Linq.Expressions;
using AuthApi.Core.Abstractions;
using AuthApi.Data.Context;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Core.Repositories
{
  public class Repository<T> : IRepository<T> where T : class
  {
    private readonly AuthApiDbContext _ctx;
    private readonly DbSet<T> _db;

    public Repository(AuthApiDbContext ctx)
    {
      _ctx = ctx;
      _db = _ctx.Set<T>();
    }

    public async Task<T> GetById(Expression<Func<T, bool>> expression = null, List<string> includes = null)
    {
      IQueryable<T> query = _db;
      if (includes != null)
      {
        foreach (var includeProp in includes)
        {
          query = query.Include(includeProp);
        }
      }

      return await query.AsNoTracking().FirstOrDefaultAsync(expression);
    }

    public async Task<IList<T>> GetAll(Expression<Func<T, bool>> expression = null,
    Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null, List<string> includes = null)
    {
      IQueryable<T> query = _db;
      if (expression != null)
      {
        query = query.Where(expression);
      }

      if (includes != null)
      {
        foreach (var includeProp in includes)
        {
          query = query.Include(includeProp);
        }
      }

      if (orderBy != null)
      {
        query = orderBy(query);
      }

      return await query.AsNoTracking().ToListAsync();
    }


    public async Task Create(T entity)
    {
      await _db.AddAsync(entity);
    }

    public async Task CreateRange(IEnumerable<T> entities)
    {
      await _db.AddRangeAsync(entities);
    }

    public async Task Delete(int id)
    {
      var entity = await _db.FindAsync(id);
      _db.Remove(entity);
    }

    public void DeleteRange(IEnumerable<T> entities)
    {
      _db.RemoveRange(entities);
    }

    public void Delete(T entity)
    {
      _db.Remove(entity);
    }

    public void Update(T entity)
    {
      _db.Attach(entity);
      _ctx.Entry(entity).State = EntityState.Modified;
    }
  }

}