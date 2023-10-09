using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Serilog;

using RegistrationVerificationLibrary;

namespace RegistrationVerification
{
    class MainCode
    {
        public static void Main()
        {
            string template = "{Timestamp: HH: mm: ss} | [{Level: u3}] | {Message: lj}{NewLine}{Exception}";
            Log.Logger = new LoggerConfiguration()
              .MinimumLevel.Debug()
              .WriteTo.Console(outputTemplate: template)
              .WriteTo.File(@"D:\Programms\ProjectsVisualStudio\RegistrationVerification\RegistrationVerification\Logs\log_file.txt", outputTemplate: template)
              .CreateLogger();

            Log.Verbose("Логгер сконфигурирован");
            Log.Information("Приложение запущено");

            Log.Information("Введите логин: ");
            string login = Console.ReadLine();
            Log.Information("Введите пароль: ");
            string password = Console.ReadLine();
            Log.Information("Введите подтверждение пароля: ");
            string passwordConfirmed = Console.ReadLine();

            RegVerif.RigistrationVerificationMethod(login, password, passwordConfirmed);

            Console.ReadKey();
            Log.CloseAndFlush();
        }
    }
}
