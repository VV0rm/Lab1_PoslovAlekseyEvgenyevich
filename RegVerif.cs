using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace RegistrationVerificationLibrary
{
    public class RegVerif
    {
        public static string RigistrationVerificationMethod(string login, string password, string passwordConfirmation)
        {
            string resultAutorization = "";

            string regLoginMail = @"^[a-zA-Z0-9.%+-]+@[a-zA-Z0-9.%+-]+\.[a-zA-Z0-9.%+-]{2,}$";
            string regLoginPhoneNumber = @"^\+\d-\d{3}-\d{3}-\d{4}";

            Log.Debug("Проверка типа логина");

            switch (TypeLogin(login))
            {
                case "Mail":
                    Log.Debug("Проверка логина на соответствие формату");
                    switch (Regex.IsMatch(login, regLoginMail, RegexOptions.IgnoreCase))
                    { 
                        case true:
                            Log.Debug("Проверка логина на уникальность");
                            if (DuplicateLogin(login) == true)
                            {
                                Log.Debug("Проверка пароля на соответствие формату");
                                switch (PasswordVerification(password))
                                {
                                    case "Accept":
                                        Log.Debug("Сравнение паролей");
                                        if (password == passwordConfirmation)
                                        {
                                            Log.Information("True");
                                            Log.Information($"Логин: {login}");
                                            ComparisonPassword(password, passwordConfirmation);
                                            resultAutorization = "Успешная регистрация";
                                            Log.Information(resultAutorization);
                                        }
                                        else
                                        {
                                            Log.Information("False");
                                            Log.Information($"Логин: {login}");
                                            ComparisonPassword(password, passwordConfirmation);
                                            resultAutorization = "Пароль и подтверждение пароля не совпадают";
                                            Log.Error(resultAutorization);
                                        }
                                        break;

                                    default:
                                        Log.Information("False");
                                        Log.Information($"Логин: {login}");
                                        ComparisonPassword(password, passwordConfirmation);
                                        resultAutorization = PasswordVerification(password);
                                        Log.Error(resultAutorization);
                                        break;
                                }
                            }
                            break;

                        case false:
                            Log.Information("False");
                            Log.Information($"Логин: {login}");
                            ComparisonPassword(password, passwordConfirmation);
                            resultAutorization = "Неправильный формат эл. почты (xxx@xxx.xxx).";
                            Log.Error(resultAutorization);
                            break;
                    }
                    break;

                case "PhoneNumber":
                    Log.Debug("Проверка логина на соответствие формату");
                    switch (Regex.IsMatch(login, regLoginPhoneNumber, RegexOptions.IgnoreCase))
                    {
                        case true:
                            Log.Debug("Проверка логина на уникальность");
                            if (DuplicateLogin(login) == true)
                            {
                                Log.Debug("Проверка пароля на соответствие формату");
                                switch (PasswordVerification(password))
                                {
                                    case "Accept":
                                        Log.Debug("Сравнение паролей");
                                        if (password == passwordConfirmation)
                                        {
                                            Log.Information("True");
                                            Log.Information($"Логин: {login}");
                                            ComparisonPassword(password, passwordConfirmation);
                                            resultAutorization = "Успешная регистрация";
                                            Log.Information(resultAutorization);
                                        }
                                        else
                                        {
                                            Log.Information("False");
                                            Log.Information($"Логин: {login}");
                                            ComparisonPassword(password, passwordConfirmation);
                                            resultAutorization = "Пароль и подтверждение пароля не совпадают";
                                            Log.Error(resultAutorization);
                                        }
                                        break;

                                    default:
                                        Log.Information("False");
                                        Log.Information($"Логин: {login}");
                                        ComparisonPassword(password, passwordConfirmation);
                                        resultAutorization = PasswordVerification(password);
                                        Log.Error(resultAutorization);
                                        break;
                                }
                            }
                            break;

                        case false:
                            Log.Information("False");
                            Log.Information($"Логин: {login}");
                            ComparisonPassword(password, passwordConfirmation);
                            resultAutorization = "Неправильный формат номера телефона (+x-xxx-xxx-xxxx).";
                            Log.Error(resultAutorization);
                            break;
                    }
                    break;

                case "JustString":
                    Log.Debug("Проверка логина на соответствие формату");
                    switch (LoginJustStringVerification(login))
                    {
                        case "Accept":
                            Log.Debug("Проверка логина на уникальность");
                            if (DuplicateLogin(login) == true)
                            {
                                Log.Debug("Проверка пароля на соответствие формату");
                                switch (PasswordVerification(password))
                                {
                                    case "Accept":
                                        Log.Debug("Сравнение паролей");
                                        if (password == passwordConfirmation)
                                        {
                                            Log.Information("True");
                                            Log.Information($"Логин: {login}");
                                            ComparisonPassword(password, passwordConfirmation);
                                            resultAutorization = "Успешная регистрация";
                                            Log.Information(resultAutorization);
                                        }
                                        else
                                        {
                                            Log.Information("False");
                                            Log.Information($"Логин: {login}");
                                            ComparisonPassword(password, passwordConfirmation);
                                            resultAutorization = "Пароль и подтверждение пароля не совпадают";
                                            Log.Error(resultAutorization);
                                        }
                                        break;

                                    default:
                                        Log.Information("False");
                                        Log.Information($"Логин: {login}");
                                        ComparisonPassword(password, passwordConfirmation);
                                        resultAutorization = PasswordVerification(password);
                                        Log.Error(resultAutorization);
                                        break;
                                }
                            }
                            break;

                        default:
                            Log.Information("False");
                            Log.Information($"Логин: {login}");
                            ComparisonPassword(password, passwordConfirmation);
                            resultAutorization = LoginJustStringVerification(login);
                            Log.Error(resultAutorization);
                            break;
                    }
                    break;

                default:
                    Log.Information("False");
                    Log.Information($"Логин: {login}");
                    ComparisonPassword(password, passwordConfirmation);
                    resultAutorization = "Неверный формат логина.";
                    Log.Error(resultAutorization);
                    break;
            }
            return resultAutorization;
        }

        private static void ComparisonPassword(string password, string passwordConfirmation)
        {
            byte[] salt = GenerateSalt();

            string hashedPassword = HashPassword(password, salt);

            Log.Information($"Маскированный пароль: {hashedPassword}");

            string hashedPasswordConfirmation = HashPassword(passwordConfirmation, salt);

            bool IsMatch = hashedPasswordConfirmation.Equals(hashedPassword);

            if (IsMatch == true)
            {
                Log.Information($"Маскированное подтверждение пароля: {hashedPasswordConfirmation}");
            }
            else
            {
                Log.Error("Маскированные пароли не совпадают.");
            }
        }

        private static string HashPassword(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000))
            {
                byte[] hash = pbkdf2.GetBytes(password.Length);
                return Convert.ToBase64String(hash);
            }
        }

        private static byte[] GenerateSalt()
        {
            byte[] salt = new byte[16]; // Размер соли 16 байт
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetNonZeroBytes(salt);
            }
            return salt;
        }

        private static string TypeLogin(string login)
        {
            string type = "";
            if(Regex.IsMatch(login, @"^(?=.*@)(?=.*\.)", RegexOptions.IgnoreCase) == true)
            {
                type = "Mail";
            }
            else if(Regex.IsMatch(login, @"^\+", RegexOptions.IgnoreCase) == true)
            {
                type = "PhoneNumber";
            }
            else
            {
                type = "JustString";
            }
            return type;
        }

        private static string PasswordVerification(string password)
        {
            string message = password.Length >= 7 ?
                             Regex.IsMatch(password, @"^(?!.*[A-Za-z])", RegexOptions.None) ?
                             Regex.IsMatch(password, @"^(?=.*[а-я])", RegexOptions.IgnoreCase) ? 
                             Regex.IsMatch(password, @"^(?=.*[А-Я])", RegexOptions.IgnoreCase) ?
                             Regex.IsMatch(password, @"^(?=.*\d)", RegexOptions.IgnoreCase) ?
                             Regex.IsMatch(password, @"^(?=.*\W)", RegexOptions.IgnoreCase)  ?
                             "Accept" : "Отсутствие спецсимволов в пароле" :
                             "Отсутствие цифр в пароле" :
                             "Отсутствие заглавных букв на кириллице в пароле" :
                             "Отсутствие строчных букв на кириллице в пароле" :
                             "Наличие латинских букв в пароле" :
                             "Длина пароля долна быть минимум 7 символов";

            return message;
        }

        private static string LoginJustStringVerification(string login)
        {
            string message = login.Length >= 5 ?
                             Regex.IsMatch(login, @"^(?!.*[А-Яа-я])", RegexOptions.None) ?
                             Regex.IsMatch(login, @"^(?=.*[A-Za-z])", RegexOptions.IgnoreCase) ?
                             Regex.IsMatch(login, @"^(?=.*\d)", RegexOptions.IgnoreCase) ?
                             Regex.IsMatch(login, @"^(?=.*_)", RegexOptions.IgnoreCase) ?
                             "Accept" : "Отсутствие символа _ в логине-строке" :
                             "Отсутствие цифр в логине-строке" :
                             "Отсутствие латинских букв в логине-строке" :
                             "Наличие букв на кириллице в логине-строке" :
                             "Длина логина долна быть минимум 5 символов";

            return message;
        }

        private static bool DuplicateLogin(string login)
        {
            bool result = true;

            string pathFile = @"D:\Programms\ProjectsVisualStudio\RegistrationVerification\RegistrationVerification\Logs\log_file.txt";

            string tempPathFile = @"D:\Programms\ProjectsVisualStudio\RegistrationVerification\RegistrationVerification\Logs\temp_log_file.txt";

            string regDuplicateLogin = $"Логин: {login}";

            try
            {
                File.Copy(pathFile, tempPathFile, true);

                string[] lines = File.ReadAllLines(tempPathFile);

                foreach (string line in lines)
                {
                    if (Regex.IsMatch(line, regDuplicateLogin))
                    {
                        Log.Error("Логин уже занят");
                        result = false;
                    }
                }
            }
            catch (IOException e)
            {
                Log.Error($"Ошибка при чтении файла: {e.Message}");
            }
            File.Delete(tempPathFile);

            return result;
        }
    }
}
