using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.PDF;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using Net.Pkcs11Interop.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SOFTHSM
{
    public class Program
    {
        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }
        static void Main(string[] args)
        {
            var factories = new Pkcs11InteropFactories();
            //string logFilePath = @"D:\SoftHSM2\Pkcs11Interop.log";
            //if (File.Exists(logFilePath))
            //    File.Delete(logFilePath);
            //// Setup logger factory implementation
            //var loggerFactory = new SimplePkcs11InteropLoggerFactory();
            //loggerFactory.MinLogLevel = Pkcs11InteropLogLevel.Trace;
            //loggerFactory.DisableConsoleOutput();
            //loggerFactory.DisableDiagnosticsTraceOutput();
            //loggerFactory.EnableFileOutput(logFilePath);

            //// Set logger factory implementation that will be used by Pkcs11Interop library
            //Pkcs11InteropLoggerFactory.SetLoggerFactory(loggerFactory);
            using (IPkcs11Library pkcs = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, @"D:\SoftHSM2\lib\softhsm2-x64.dll", AppType.MultiThreaded))
            {
                var slots = pkcs.GetSlotList(SlotsType.WithTokenPresent);

                using (ISession session = slots[0].OpenSession(SessionType.ReadWrite))
                {
                    //login
                    session.Login(CKU.CKU_USER, "manishuser2208");

                    
                    //// Prepare attribute template of new public key
                    //List<IObjectAttribute> pubKeyAttributes = new List<IObjectAttribute>();
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "Manish_Label"));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, "ManishKey2"));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 4096));
                    //pubKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

                    //// Prepare attribute template of new private key
                    //List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "Manish_Label"));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, "ManishKey2"));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
                    //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));

                    //IMechanism mech = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

                    //IObjectHandle publicKeyHandle = null;
                    //IObjectHandle privateKeyHandle = null;
                    //session.GenerateKeyPair(mech, pubKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);


                    // Prepare attribute template that defines search criteria
                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, "ManishKey2"));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));

                    List<IObjectAttribute> objectAttributesPr = new List<IObjectAttribute>();
                    objectAttributesPr.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, "ManishKey2"));
                    objectAttributesPr.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));

                    session.FindObjectsInit(objectAttributesPr);

                    List<IObjectHandle> foundObjectsPr = session.FindObjects(5);

                    session.FindObjectsFinal();

                    // Initialize searching
                    session.FindObjectsInit(objectAttributes);

                    // Get search results
                    List<IObjectHandle> foundObjects = session.FindObjects(5);

                    // Terminate searching
                    session.FindObjectsFinal();
                    Pkcs11RsaSignature pkcssign = new Pkcs11RsaSignature(@"D:\SoftHSM2\lib\softhsm2-x64.dll", null, @"Manish_Label", @"manishuser2208", @"Manish_Label", @"ManishKey2", Net.Pkcs11Interop.PDF.HashAlgorithm.SHA256);
                    var certs = pkcssign.GetAllCertificates();

                    //session.DestroyObject(foundObjects[0]);

                    List<CKA> pubKeyAttrsToRead = new List<CKA>();
                    pubKeyAttrsToRead.Add(CKA.CKA_KEY_TYPE);
                    pubKeyAttrsToRead.Add(CKA.CKA_MODULUS);
                    pubKeyAttrsToRead.Add(CKA.CKA_PUBLIC_EXPONENT);

                    // Read public key attributes
                    List<IObjectAttribute> publicKeyAttributes = session.GetAttributeValue(foundObjects[0], pubKeyAttrsToRead);

                    //BigInteger modulus = new BigInteger(1, publicKeyAttributes[1].GetValueAsByteArray());
                    //BigInteger publicExponent = new BigInteger(1, publicKeyAttributes[2].GetValueAsByteArray());
                    //RsaKeyParameters publicKeyParameters = new RsaKeyParameters(false, modulus, publicExponent);


                    string countryName = "IN";
                    string stateOrProvinceName = "KAR";
                    string localityName = "BLR";
                    //string organizationName = "Techno800";
                    //string commonName = "Techno800";
                    //string signatureAlgorihtm = PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;
                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);

                    //Pkcs10CertificationRequestDelaySigned pkcs10 = new Pkcs10CertificationRequestDelaySigned(signatureAlgorihtm, new X509Name("C=" + countryName + ",ST=" + stateOrProvinceName + ",L=" + localityName + ",O=" + organizationName + ",CN=" + commonName), publicKeyParameters, null);
                    //var dataToSign = pkcs10.GetDataToSign();
                    

                    //byte[] signature = session.Sign(mechanism, foundObjectsPr[0], dataToSign);
                    //pkcs10.SignRequest(new DerBitString(signature));

                    //var csr = pkcs10.GetDerEncoded();
                    //var str = Convert.ToBase64String(csr);

                    //// Adding \n after every 64 characters
                    //var builder = new StringBuilder();
                    //int count = 0;

                    //foreach (var c in str)
                    //{
                    //    builder.Append(c);
                    //    if ((++count % 64) == 0)
                    //    {
                    //        builder.Append('\n');
                    //    }
                    //}

                    //str = builder.ToString();

                    //// Adding comments in Certificate start and end
                    //string add = string.Empty;

                    //if (str.Substring(str.Length - 2, 2) != "\n")
                    //{
                    //    add = "\n";
                    //}

                    //str = "-----BEGIN CERTIFICATE REQUEST-----\n" + str + add + "-----END CERTIFICATE REQUEST-----";

                    //File.WriteAllText(@"D:\SoftHSM2\\ex.csr", str);


                    //Signing of device public key
                    //var dpk = File.ReadAllText(@"C:\Technoforte\IDM\Database\DevicePublicKey.csr");
                    RSA rsa = RSA.Create(4096);

                    X500DistinguishedName distinguishedName = new X500DistinguishedName("C=" + countryName + ",ST=" + stateOrProvinceName + ",L=" + localityName + ",O=FACE,CN=FACE");

                    //Device public key
                    CertificateRequest request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));
                    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                    //mosip signed certificate
                    var msc = File.ReadAllBytes(@"D:\ca_cert.crt");
                    var mosipSigned = new X509Certificate2(msc);
                    //var pubKey = mosipSigned.GetRSAPublicKey();
                    var mosipsc = mosipSigned.CopyWithPrivateKey(RSA.Create(new RSAParameters{D = publicKeyAttributes[2].GetValueAsByteArray(), Modulus = publicKeyAttributes[1].GetValueAsByteArray() }));

                    //Signed Certificate
                    X500DistinguishedName distinguishedNameMosip = new X500DistinguishedName("C=IN,ST=KA,L=BANGALORE,O=IITB,CN=www.mosip.io");
                    var sc = request.Create(mosipsc, DateTimeOffset.UtcNow.AddSeconds(-10), DateTimeOffset.UtcNow.AddDays(30), new byte[] { 05 });

                    //Signed device public key
                    //var signature = session.Sign(mechanism, foundObjectsPr[0], request.CreateSigningRequest());
                    //var signatureF = session.Sign(mechanism, foundObjectsPr[0], signature);
                    //var sdpk = Base64UrlEncode(signature);
                    //var crt = new X509Certificate2(signature);


                    //var stri = Convert.ToBase64String(sdpk);


                    // Parse certificate
                    //var msc = File.ReadAllBytes(@"C:\Technoforte\IDM\Database\mosip-signed.crt");
                    //X509CertificateParser x509CertificateParser = new X509CertificateParser();
                    //X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(msc);

                    //// Get public key from certificate
                    //AsymmetricKeyParameter pubKeyParams = x509Certificate.GetPublicKey();

                    //RsaKeyParameters rsaPubKeyParams = (RsaKeyParameters)pubKeyParams;

                    //// Find corresponding private key
                    //List<IObjectAttribute> privKeySearchTemplate = new List<IObjectAttribute>();
                    //privKeySearchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                    //privKeySearchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
                    //privKeySearchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus.ToByteArrayUnsigned()));
                    //privKeySearchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent.ToByteArrayUnsigned()));

                    //List<IObjectHandle> foundObjectsPrMosip = session.FindAllObjects(privKeySearchTemplate);


                    //IObjectHandle privKeyObjectHandle = foundObjectsPrMosip[0];

                    //// Read CKA_LABEL and CKA_ID attributes of private key
                    //List<CKA> privKeyAttrsToRead = new List<CKA>();
                    //privKeyAttrsToRead.Add(CKA.CKA_LABEL);
                    //privKeyAttrsToRead.Add(CKA.CKA_ID);

                    //List<IObjectAttribute> privKeyAttributes = session.GetAttributeValue(privKeyObjectHandle, privKeyAttrsToRead);

                    //// Define attributes of new certificate object
                    //List<IObjectAttribute> certificateAttributes = new List<IObjectAttribute>();
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, privKeyAttributes[0].GetValueAsString()));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TRUSTED, false));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, privKeyAttributes[1].GetValueAsByteArray()));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, x509Certificate.SerialNumber.ToByteArrayUnsigned()));
                    //certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, x509Certificate.GetEncoded()));

                    //// Create certificate object
                    //session.CreateObject(certificateAttributes);



                    //session.Logout();
                }
            }
        }
    }
}
