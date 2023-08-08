using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace MCDRDigitalSignatureClient.Controllers
{
    public class SignerController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public string signHash(string hash, string certSerial)
        {
            byte[] data = Convert.FromBase64String(hash);
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.MaxAllowed);

            var foundCerts = store.Certificates.Find(X509FindType.FindBySerialNumber, certSerial, false);
            if (foundCerts.Count == 0)
            {
                return "Certificate Not Found";
            }

            X509Certificate2 cert = foundCerts[0];

            var privKy = cert.GetRSAPrivateKey();

            byte[] signedData = privKy.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signedData);
        }
    }
}
