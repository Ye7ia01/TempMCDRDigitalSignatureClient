//using iText.Kernel.Geom;
//using iText.Kernel.Pdf;
//using iText.Signatures;
using iText.Commons.Bouncycastle.Asn1;
using iText.Commons.Bouncycastle.Asn1.X500;
using iText.Commons.Bouncycastle.Cert;
using iText.Commons.Bouncycastle.Crypto;
using iText.Commons.Bouncycastle.Math;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.Collections;
//using System.Security.Cryptography.X509Certificates;
//using System.Security.Cryptography.X509Certificates;
using System.Text;
using XSystem.Security.Cryptography;
using static iText.Signatures.PdfSigner;
using ITSAClient = iText.Signatures.ITSAClient;
using PdfPKCS7 = iTextSharp.text.pdf.security.PdfPKCS7;

namespace MCDRDigitalSignatureClient.Controllers
{


    class MyExternalSignatureContainer : IExternalSignatureContainer
    {
        public byte[] Data;
        public void ModifySigningDictionary(PdfDictionary signDic)
        {
            throw new NotImplementedException();
        }

        public byte[] getData()
        {
            return this.Data;
        }

        public byte[] Sign(Stream inputStream)
        {

            this.Data = DigestAlgorithms.Digest(inputStream, DigestAlgorithms.SHA256);
            return new byte[0];
           
        }

        public class SignedSignatureContainer : IExternalSignatureContainer
        {
            public byte[] Hash { get; set; }
            public byte[] SignedHash { get; set; }
            public X509Certificate[] CertChains { get; set; }

            public SignedSignatureContainer(byte[] hash, byte[] signedHash, X509Certificate[] certCertChains)
            {
                this.Hash = hash;
                this.SignedHash = signedHash;
                this.CertChains = certCertChains;
            }

            public byte[] Sign(Stream data)
            {
                PdfPKCS7 sgn = new PdfPKCS7(null, CertChains, "SHA256", false);
                
                sgn.SetExternalDigest(this.SignedHash, null, "RSA");

                ITSAClient tsaClient = new iText.Signatures.TSAClientBouncyCastle("http://tsa.mcsd.com.eg/mcdrca2022/tsa");
                return sgn.GetEncodedPKCS7(this.Hash, null, null, null, iTextSharp.text.pdf.security.CryptoStandard.CMS);
            }

            public void ModifySigningDictionary(PdfDictionary signDic)
            {
                signDic.Put(PdfName.Filter, PdfName.Adobe_PPKLite);
                signDic.Put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
            }
        }


        [ApiController]
        [Route("[controller]")]
        public class SignerController : Controller
        {
            public IActionResult Index()
            {
                return View();
            }

            
            [HttpPost(Name = "preparePDF")]
            public void testPrepare()
            {
                string src = "C:\\Users\\ye7ia\\Desktop\\Doc1.pdf";
                string dest = "C:\\Users\\ye7ia\\Desktop\\Doc1_signAgilityTest.pdf";
                System.Security.Cryptography.X509Certificates.X509Certificate2Collection certificates;
                System.Security.Cryptography.X509Certificates.X509Store my = new System.Security.Cryptography.X509Certificates.X509Store(System.Security.Cryptography.X509Certificates.StoreName.My, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
                my.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                certificates  = my.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindBySerialNumber, "724e3ce5e791ac3b5c4512324955d649", false);
                if (certificates.Count == 0) throw new Exception("No certificates found.");

                System.Security.Cryptography.X509Certificates.X509Certificate2 cert = certificates[0];

                System.Security.Cryptography.X509Certificates.X509Chain chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                //chain.Build(cert);

                X509Certificate bouncyCert = DotNetUtilities.FromX509Certificate(cert);

                X509Certificate[] certChain = new X509Certificate[1];
                certChain[0] = bouncyCert;





                preparePdfDoc(src, dest, "field", certChain);
            }







            // Backend Module
            public string preparePdfDoc(String src, String dest, String fieldname, X509Certificate[] chain)
            {
                PdfReader reader = new PdfReader(src);
                PdfSigner signer = new PdfSigner(reader, new FileStream(dest, FileMode.Create), new StampingProperties());

                PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
                appearance
                    .SetPageRect(new Rectangle(36, 748, 200, 100))
                    .SetPageNumber(1)
                    .SetCertificate(new iText.Bouncycastle.X509.X509CertificateBC(chain[0]));
                signer.SetFieldName(fieldname);

                /* ExternalBlankSignatureContainer constructor will create the PdfDictionary for the signature
                 * information and will insert the /Filter and /SubFilter values into this dictionary.
                 * It will leave just a blank placeholder for the signature that is to be inserted later.
                 */
                MyExternalSignatureContainer external = new MyExternalSignatureContainer();

                // Sign the document using an external container
                // 8192 is the size of the empty signature placeholder.
                signer.SignExternalContainer(external, 8192);
                byte[] hash = external.Data;

                // If Doesnot work , return the above hash and try again later.
                
                PdfPKCS7 signature = new PdfPKCS7(null, chain, "SHA265", false);

                
                var authAttributes = signature.getAuthenticatedAttributeBytes(hash,null,null,iTextSharp.text.pdf.security.CryptoStandard.CMS);
                return Convert.ToBase64String(SHA256Managed.Create().ComputeHash(authAttributes));
                
            }



            // Backend Module
            public static void embedSignaturePdf(string tempFile, string targetFile, X509Certificate[] chain, byte[] hash, byte[] signedHash)
            {
                using (PdfReader reader = new PdfReader(tempFile))
                {
                    using (FileStream outStream = System.IO.File.OpenWrite(targetFile))
                    {
                        var signedContainer = new SignedSignatureContainer(hash, signedHash, chain);
                        PdfSigner signer = new PdfSigner(reader, outStream, new StampingProperties());
                        PdfSigner.SignDeferred(signer.GetDocument(),"field",outStream,signedContainer);
                    }
                }
            }






        }

        public class cert : IX509Certificate
        {
            public void CheckValidity(DateTime time)
            {
                throw new NotImplementedException();
            }

            public ISet<string> GetCriticalExtensionOids()
            {
                throw new NotImplementedException();
            }

            public byte[] GetEncoded()
            {
                throw new NotImplementedException();
            }

            public string GetEndDateTime()
            {
                throw new NotImplementedException();
            }

            public IList GetExtendedKeyUsage()
            {
                throw new NotImplementedException();
            }

            public IAsn1OctetString GetExtensionValue(string oid)
            {
                throw new NotImplementedException();
            }

            public IX500Name GetIssuerDN()
            {
                throw new NotImplementedException();
            }

            public DateTime GetNotBefore()
            {
                throw new NotImplementedException();
            }

            public IPublicKey GetPublicKey()
            {
                throw new NotImplementedException();
            }

            public IBigInteger GetSerialNumber()
            {
                throw new NotImplementedException();
            }

            public IX500Name GetSubjectDN()
            {
                throw new NotImplementedException();
            }

            public byte[] GetTbsCertificate()
            {
                throw new NotImplementedException();
            }

            public void Verify(IPublicKey issuerPublicKey)
            {
                throw new NotImplementedException();
            }
        }
    }
}

