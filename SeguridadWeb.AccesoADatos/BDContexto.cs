using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// ********************************
using Microsoft.EntityFrameworkCore;
using SeguridadWeb.EntidadesDeNegocio;

namespace SeguridadWeb.AccesoADatos
{
    public class BDContexto: DbContext
    {
        public DbSet<Rol> Rol { get; set; }
        public DbSet<Usuario> Usuario { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            //optionsBuilder.UseSqlServer(@"Catalog=BDejemplo503;User ID=jramosmartinez92_SQLLogin_3;Password=c8b3q6b4iq;Connect Timeout=30;Encrypt=False;TrustServerCertificate=False;ApplicationIntent=ReadWrite;MultiSubnetFailover=False");
            optionsBuilder.UseSqlServer(@"workstation id=BDejemplo503.mssql.somee.com;packet size=4096;user id=jramosmartinez92_SQLLogin_3;pwd=c8b3q6b4iq;data source=BDejemplo503.mssql.somee.com;persist security info=False;initial catalog=BDejemplo503;Encrypt=False;TrustServerCertificate=False;");
        }
    }
}
