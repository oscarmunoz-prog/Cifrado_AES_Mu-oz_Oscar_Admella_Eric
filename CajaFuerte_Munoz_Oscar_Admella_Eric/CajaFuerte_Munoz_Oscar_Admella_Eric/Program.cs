/*
 * 
 *  CajaFuerte — cifrado y descifrado de ficheros .txt con contraseña
 * 
 *
 *  Uso:
 *    CajaFuerte cifrar    <fichero_entrada.txt>  <fichero_salida.caja>  [contraseña]
 *    CajaFuerte descifrar <fichero_salida.caja>  <fichero_recuperado>   [contraseña]
 *
 *  Si se omite la contraseña, se pide por teclado sin mostrarla.
 *
 *  Primitivas (solo System.Security.Cryptography, sin dependencias externas):
 *    - Cifrado  AES-256 en modo GCM (cifrado autenticado: confidencialidad + integridad)
 *    - Derivación clave  PBKDF2 (Rfc2898DeriveBytes) con HMAC-SHA256, 600.000 iteraciones
 *    - Aleatoriedad  RandomNumberGenerator (CSPRNG del sistema operativo)
 *
 * 
 *  FORMATO BINARIO DEL FICHERO .caja
 * 
 *  Todos los bloques tienen longitud FIJA salvo el último, que ocupa el resto del fichero.
 *
 *   Offset (dec) Offset (hex)  Tamaño   Contenido
 * 
 *        0       0x00          4 bytes  Número mágico: 43 41 4A 41
 *        4       0x04          1 byte   Versión del formato: 01
 *        5       0x05         16 bytes  SAL aleatoria de PBKDF2
 *       21       0x15         12 bytes  NONCE  aleatorio de AES-GCM
 *       33       0x21         16 bytes  TAG de autenticación de GCM
 *       49       0x31          N bytes  TEXTO CIFRADO (N = tamaño del .txt original; GCM no
 *                                       añade relleno) hasta el final del fichero
 *
 *  Tamaño total = 49 + N bytes.
 *
 *  Ejemplo de vista hexadecimal (los valores de sal, nonce y tag cambian en cada cifrado):
 *
 *   00000000  43 41 4A 41 01 ss ss ss  ss ss ss ss ss ss ss ss   CAJA. + sal
 *   00000010  ss ss ss ss ss nn nn nn  nn nn nn nn nn nn nn nn   sal + nonce
 *   00000020  nn tt tt tt tt tt tt tt  tt tt tt tt tt tt tt tt   nonce + tag
 *   00000030  tt cc cc cc cc                                     tag + texto cifrado
 *
 *  Integridad:
 *    - El tag de GCM cubre el texto cifrado.
 *    - La cabecera se pasa a GCM como datos asociados" no se cifra, pero
 *      cualquier cambio en ella también invalida el tag.
 *    - Si se altera la sal, se deriva otra clave y el tag tampoco coincide.
 *    - Modificar cualquier byte del fichero hace que el descifrado sea rechazado.
 *
 *  La lógica criptográfica está en CifradorCaja.cs; este fichero solo gestiona la consola,
 *  la validación de argumentos y la lectura/escritura en disco.
 *
 */

using System.Security.Cryptography;

namespace CajaFuerte;

internal static class Program
{
    // Códigos de salida, para poder usar el programa desde scripts.
    private const int SalidaOk = 0;
    private const int SalidaErrorUso = 1;
    private const int SalidaErrorFichero = 2;
    private const int SalidaIntegridadFallida = 3;
    private const int SalidaErrorInesperado = 4;

    // Política mínima de contraseñas al cifrar (al descifrar se acepta lo que se usó en su día).
    private const int LongitudMinimaContrasena = 12;

    // AesGcm cifra en memoria de una sola vez, se limita el tamaño para no agotar la RAM.
    private const long TamanoMaximoBytes = 256L * 1024 * 1024; // 256 MiB

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length is < 3 or > 4)
            {
                MostrarUso();
                return SalidaErrorUso;
            }

            string operacion = args[0].ToLowerInvariant();
            string rutaEntrada = args[1];
            string rutaSalida = args[2];
            string? contrasenaArgumento = args.Length == 4 ? args[3] : null;

            switch (operacion)
            {
                case "cifrar":
                    EjecutarCifrado(rutaEntrada, rutaSalida, contrasenaArgumento);
                    Console.WriteLine($"Fichero cifrado correctamente: {rutaSalida}");
                    return SalidaOk;

                case "descifrar":
                    EjecutarDescifrado(rutaEntrada, rutaSalida, contrasenaArgumento);
                    Console.WriteLine($"Integridad verificada. Fichero descifrado correctamente: {rutaSalida}");
                    return SalidaOk;

                default:
                    Console.Error.WriteLine($"Error: operación desconocida '{args[0]}'.");
                    MostrarUso();
                    return SalidaErrorUso;
            }
        }
        catch (ErrorDeUsoException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return SalidaErrorUso;
        }
        catch (FormatoCajaInvalidoException ex)
        {
            Console.Error.WriteLine($"ERROR DE INTEGRIDAD: el fichero no es un .caja válido: {ex.Message}");
            Console.Error.WriteLine("No se ha generado ningún fichero de salida.");
            return SalidaIntegridadFallida;
        }
        catch (AuthenticationTagMismatchException)
        {
            // GCM no distingue entre contraseña incorrecta y fichero alterado,
            // en ambos casos el tag calculado no coincide con el almacenado.
            Console.Error.WriteLine("ERROR DE INTEGRIDAD: la contraseña es incorrecta o el fichero ha sido manipulado.");
            Console.Error.WriteLine("Se ha rechazado el descifrado y no se ha generado ningún fichero de salida.");
            return SalidaIntegridadFallida;
        }
        catch (CryptographicException ex)
        {
            Console.Error.WriteLine($"Error criptográfico: {ex.Message}");
            Console.Error.WriteLine("No se ha generado ningún fichero de salida.");
            return SalidaIntegridadFallida;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"Error de acceso a fichero: {ex.Message}");
            return SalidaErrorFichero;
        }
        catch (PlatformNotSupportedException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return SalidaErrorInesperado;
        }
    }

    private static void EjecutarCifrado(string rutaEntrada, string rutaSalida, string? contrasenaArgumento)
    {
        ValidarExtension(rutaEntrada, ".txt", "El fichero de entrada debe ser un .txt");
        ValidarExtension(rutaSalida, ".caja", "El fichero cifrado debe tener extensión .caja");
        ValidarRutas(rutaEntrada, rutaSalida);

        char[] contrasena = ObtenerContrasena(contrasenaArgumento, confirmar: true);
        byte[]? textoPlano = null;
        try
        {
            if (contrasena.Length < LongitudMinimaContrasena)
            {
                throw new ErrorDeUsoException(
                    $"La contraseña debe tener al menos {LongitudMinimaContrasena} caracteres.");
            }

            textoPlano = File.ReadAllBytes(rutaEntrada);
            byte[] contenidoCaja = CifradorCaja.Cifrar(textoPlano, contrasena);
            EscribirSinSobrescribir(rutaSalida, contenidoCaja);
        }
        finally
        {
            Array.Clear(contrasena);
            if (textoPlano is not null)
            {
                CryptographicOperations.ZeroMemory(textoPlano);
            }
        }
    }

    private static void EjecutarDescifrado(string rutaEntrada, string rutaSalida, string? contrasenaArgumento)
    {
        ValidarExtension(rutaEntrada, ".caja", "El fichero a descifrar debe tener extensión .caja");
        ValidarRutas(rutaEntrada, rutaSalida);

        char[] contrasena = ObtenerContrasena(contrasenaArgumento, confirmar: false);
        byte[]? textoPlano = null;
        try
        {
            byte[] contenidoCaja = File.ReadAllBytes(rutaEntrada);
            // Si la verificación falla, descifrar lanza la excepción antes de que se escriba nada,
            // nunca se generan datos corruptos o manipulados en disco.
            textoPlano = CifradorCaja.Descifrar(contenidoCaja, contrasena);
            EscribirSinSobrescribir(rutaSalida, textoPlano);
        }
        finally
        {
            Array.Clear(contrasena);
            if (textoPlano is not null)
            {
                CryptographicOperations.ZeroMemory(textoPlano);
            }
        }
    }

    private static char[] ObtenerContrasena(string? contrasenaArgumento, bool confirmar)
    {
        if (contrasenaArgumento is not null)
        {
            Console.Error.WriteLine(
                "Aviso: la contraseña pasada como argumento queda visible en el historial de la consola. " +
                "Omítela para introducirla de forma oculta.");
            return contrasenaArgumento.ToCharArray();
        }

        char[] contrasena = ConsolaSegura.LeerContrasenaOculta("Contraseña: ");
        if (!confirmar)
        {
            return contrasena;
        }

        char[] repeticion = ConsolaSegura.LeerContrasenaOculta("Repite la contraseña: ");
        try
        {
            if (!contrasena.AsSpan().SequenceEqual(repeticion))
            {
                Array.Clear(contrasena);
                throw new ErrorDeUsoException("Las contraseñas no coinciden.");
            }
            return contrasena;
        }
        finally
        {
            Array.Clear(repeticion);
        }
    }

    private static void ValidarExtension(string ruta, string extension, string mensaje)
    {
        if (!string.Equals(Path.GetExtension(ruta), extension, StringComparison.OrdinalIgnoreCase))
        {
            throw new ErrorDeUsoException($"{mensaje}: '{ruta}'.");
        }
    }

    private static void ValidarRutas(string rutaEntrada, string rutaSalida)
    {
        if (!File.Exists(rutaEntrada))
        {
            throw new ErrorDeUsoException($"No existe el fichero de entrada '{rutaEntrada}'.");
        }
        if (string.Equals(Path.GetFullPath(rutaEntrada), Path.GetFullPath(rutaSalida), StringComparison.OrdinalIgnoreCase))
        {
            throw new ErrorDeUsoException("El fichero de entrada y el de salida no pueden ser el mismo.");
        }
        if (File.Exists(rutaSalida))
        {
            throw new ErrorDeUsoException($"El fichero de salida '{rutaSalida}' ya existe; no se sobrescribe.");
        }
        long tamano = new FileInfo(rutaEntrada).Length;
        if (tamano > TamanoMaximoBytes)
        {
            throw new ErrorDeUsoException(
                $"El fichero de entrada supera el máximo permitido ({TamanoMaximoBytes / (1024 * 1024)} MiB).");
        }
    }

    
    /// Escribe primero en un temporal del mismo directorio y luego lo renombra, así nunca queda
    /// un fichero de salida a medias si el proceso falla, y nunca se pisa un fichero existente.
    
    private static void EscribirSinSobrescribir(string ruta, byte[] contenido)
    {
        string rutaCompleta = Path.GetFullPath(ruta);
        string directorio = Path.GetDirectoryName(rutaCompleta) ?? ".";
        string temporal = Path.Combine(directorio, $".{Path.GetFileName(rutaCompleta)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var flujo = new FileStream(temporal, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                flujo.Write(contenido);
                flujo.Flush(flushToDisk: true);
            }
            File.Move(temporal, rutaCompleta, overwrite: false);
        }
        finally
        {
            if (File.Exists(temporal))
            {
                File.Delete(temporal);
            }
        }
    }

    private static void MostrarUso()
    {
        Console.Error.WriteLine("""
            Uso:
              CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> [contraseña]
              CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado>  [contraseña]

            Si no se indica la contraseña, se pedirá por teclado sin mostrarla (recomendado).
            """);
    }
}

/// Error en los argumentos o en los datos introducidos por el usuario.
internal sealed class ErrorDeUsoException : Exception
{
    public ErrorDeUsoException(string mensaje) : base(mensaje) { }
}
