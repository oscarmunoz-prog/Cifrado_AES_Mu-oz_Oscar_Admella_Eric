using System.Security.Cryptography;

namespace CajaFuerte;

/// Lógica criptográfica de CajaFuerte: AES-256-GCM con clave derivada por PBKDF2-HMAC-SHA256.
/// No toca la consola ni el disco, recibe bytes y devuelve bytes, para que se pueda revisar
/// y auditar de forma aislada. El formato binario está documentado al principio de Program.cs.

internal static class CifradorCaja
{
    // Constantes del formato
    // CAJA en ASCII permite reconocer el tipo de fichero en un editor hexadecimal.
    private static readonly byte[] NumeroMagico = "CAJA"u8.ToArray();
    private const byte VersionFormato = 1;

    private const int TamanoCabecera = 5;   // 4 bytes número mágico + 1 byte versión
    public const int TamanoSal = 16;        // 128 bits (mínimo exigido: 16 bytes)
    public const int TamanoNonce = 12;      // 96 bits: tamaño recomendado por NIST SP 800-38D para GCM
    public const int TamanoTag = 16;        // 128 bits: tag de autenticación completo
    private const int TamanoClave = 32;     // 256 bits -> AES-256

    // OWASP Password Storage Cheat Sheet: PBKDF2-HMAC-SHA256 con al menos 600.000 iteraciones.
    // Va ligado a la versión del formato: si algún día se sube, se crea la versión 2.
    private const int IteracionesPbkdf2 = 600_000;

    private const int OffsetSal = TamanoCabecera;                 // 5
    private const int OffsetNonce = OffsetSal + TamanoSal;        // 21
    private const int OffsetTag = OffsetNonce + TamanoNonce;      // 33
    public const int OffsetCifrado = OffsetTag + TamanoTag;       // 49 = tamaño mínimo de un .caja

    
    /// Cifra <paramref name="textoPlano"/> y devuelve el contenido completo del fichero .caja.
   
    public static byte[] Cifrar(ReadOnlySpan<byte> textoPlano, ReadOnlySpan<char> contrasena)
    {
        ComprobarSoporteGcm();

        byte[] resultado = new byte[OffsetCifrado + textoPlano.Length];
        Span<byte> salida = resultado;

        // Cabecera (número mágico + versión). Se autentica como "datos asociados" (AAD).
        NumeroMagico.CopyTo(salida);
        salida[4] = VersionFormato;

        // Sal y nonce nuevos en cada cifrado, sacados del generador criptográfico del sistema.
        // Nunca constantes, nunca System.Random, nunca derivados de la contraseña.
        Span<byte> sal = salida.Slice(OffsetSal, TamanoSal);
        Span<byte> nonce = salida.Slice(OffsetNonce, TamanoNonce);
        RandomNumberGenerator.Fill(sal);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> tag = salida.Slice(OffsetTag, TamanoTag);
        Span<byte> textoCifrado = salida.Slice(OffsetCifrado);

        byte[] clave = DerivarClave(contrasena, sal);
        try
        {
            using var aes = new AesGcm(clave, TamanoTag);
            aes.Encrypt(nonce, textoPlano, textoCifrado, tag, salida[..TamanoCabecera]);
        }
        finally
        {
            // La clave no debe quedarse en memoria más tiempo del necesario.
            CryptographicOperations.ZeroMemory(clave);
        }

        return resultado;
    }

    
    /// Verifica y descifra un fichero .caja. Si la contraseña es incorrecta o cualquier byte del
    /// fichero se ha modificado, lanza <see cref="AuthenticationTagMismatchException"/> y no
    /// devuelve ningún dato, GCM comprueba el tag antes de entregar el texto plano.
    /// <exception cref="FormatoCajaInvalidoException">El fichero no tiene el formato esperado.</exception>
    /// <exception cref="AuthenticationTagMismatchException">Contraseña incorrecta o fichero manipulado.</exception>
    public static byte[] Descifrar(ReadOnlySpan<byte> contenidoCaja, ReadOnlySpan<char> contrasena)
    {
        ComprobarSoporteGcm();

        if (contenidoCaja.Length < OffsetCifrado)
        {
            throw new FormatoCajaInvalidoException(
                $"el fichero mide {contenidoCaja.Length} bytes y un .caja válido mide al menos {OffsetCifrado}.");
        }
        if (!contenidoCaja[..NumeroMagico.Length].SequenceEqual(NumeroMagico))
        {
            throw new FormatoCajaInvalidoException("no empieza por la firma 'CAJA'; no es un fichero de CajaFuerte.");
        }
        if (contenidoCaja[4] != VersionFormato)
        {
            throw new FormatoCajaInvalidoException($"versión de formato {contenidoCaja[4]} no soportada (se esperaba {VersionFormato}).");
        }

        ReadOnlySpan<byte> cabecera = contenidoCaja[..TamanoCabecera];
        ReadOnlySpan<byte> sal = contenidoCaja.Slice(OffsetSal, TamanoSal);
        ReadOnlySpan<byte> nonce = contenidoCaja.Slice(OffsetNonce, TamanoNonce);
        ReadOnlySpan<byte> tag = contenidoCaja.Slice(OffsetTag, TamanoTag);
        ReadOnlySpan<byte> textoCifrado = contenidoCaja[OffsetCifrado..];

        byte[] textoPlano = new byte[textoCifrado.Length];
        byte[] clave = DerivarClave(contrasena, sal);
        try
        {
            using var aes = new AesGcm(clave, TamanoTag);
            // Comprobación de integridad explícita, si el tag no coincide, decrypt lanza la
            // excepción y borra el búfer de salida. No se captura aquí, la decide quien llama.
            aes.Decrypt(nonce, textoCifrado, tag, textoPlano, cabecera);
            return textoPlano;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(textoPlano);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clave);
        }
    }

    ///PBKDF2 con HMAC-SHA256 → clave de 256 bits.
    private static byte[] DerivarClave(ReadOnlySpan<char> contrasena, ReadOnlySpan<byte> sal)
    {
        byte[] clave = new byte[TamanoClave];
        // La sobrecarga con ReadOnlySpan<char> codifica la contraseña en UTF-8 internamente.
        Rfc2898DeriveBytes.Pbkdf2(contrasena, sal, clave, IteracionesPbkdf2, HashAlgorithmName.SHA256);
        return clave;
    }

    private static void ComprobarSoporteGcm()
    {
        if (!AesGcm.IsSupported)
        {
            // No hay alternativa silenciosa a un modo más débil: si no hay GCM, no se cifra.
            throw new PlatformNotSupportedException("Esta plataforma no soporta AES-GCM.");
        }
    }
}

/// El fichero no es un .caja reconocible (firma, versión o tamaño incorrectos).
internal sealed class FormatoCajaInvalidoException : Exception
{
    public FormatoCajaInvalidoException(string mensaje) : base(mensaje) { }
}
