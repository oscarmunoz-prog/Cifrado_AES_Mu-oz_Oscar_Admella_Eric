namespace CajaFuerte;


/// Lectura de la contraseña por teclado sin mostrarla en pantalla.
/// Se devuelve un char[] (y no un string) para poder borrarlo de memoria después de usarlo:
/// los string de .NET son inmutables y no se pueden sobrescribir.

internal static class ConsolaSegura
{
    private const int LongitudMaxima = 1024;

    public static char[] LeerContrasenaOculta(string mensaje)
    {
        Console.Error.Write(mensaje);

        // Si la entrada viene de una tubería (scripts), no hay teclado, se lee una línea.
        if (Console.IsInputRedirected)
        {
            string? linea = Console.In.ReadLine();
            Console.Error.WriteLine();
            return (linea ?? string.Empty).ToCharArray();
        }

        char[] bufer = new char[LongitudMaxima];
        int longitud = 0;
        try
        {
            while (true)
            {
                ConsoleKeyInfo tecla = Console.ReadKey(intercept: true); // intercept: no se hace eco
                if (tecla.Key == ConsoleKey.Enter)
                {
                    break;
                }
                if (tecla.Key == ConsoleKey.Backspace)
                {
                    if (longitud > 0)
                    {
                        bufer[--longitud] = '\0';
                        Console.Error.Write("\b \b");
                    }
                    continue;
                }
                if (char.IsControl(tecla.KeyChar))
                {
                    continue;
                }
                if (longitud == LongitudMaxima)
                {
                    throw new ErrorDeUsoException($"La contraseña no puede superar {LongitudMaxima} caracteres.");
                }
                bufer[longitud++] = tecla.KeyChar;
                Console.Error.Write('*');
            }
            Console.Error.WriteLine();
            return bufer.AsSpan(0, longitud).ToArray();
        }
        finally
        {
            Array.Clear(bufer);
        }
    }
}
