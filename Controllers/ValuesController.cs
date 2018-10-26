using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;
using System.Xml;
using System.Xml.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace SignRouteOneXMLService.Controllers
{
    public class ValuesController : ControllerBase
    {
        public static string STR_SOAP_NS { get; private set; }
        public static string STR_SOAPSEC_NS { get; private set; }
        public static string STR_SOAP_ENV { get; private set; }
        private XmlNamespaceManager nameManager;

        [HttpPost]
        public bool AddCertificationDetails()
        {
            return true;
            //write insert logic  

        }
        [HttpGet]
        public string GetService()
        {
            return "test return ";

        }
        [HttpPut]
        public string SignUnsignedWithCert([FromBody] string unsignedXMLText)
        {

            STR_SOAPSEC_NS = "http://schemas.xmlsoap.org/soap/security/2000-12";
            STR_SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
            STR_SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/";
//            HttpContent requestContent = Request.Body;
//            Byte[] BPostData = requestContent.ReadAsByteArrayAsync().Result;
//            UTF8Encoding encoding = new UTF8Encoding();
//            //Convert the bytes to string using Encoding class
//            String unsignedXMLText = encoding.GetString(BPostData);
            XmlDocument unsignedXML = new XmlDocument();
            unsignedXML.LoadXml(unsignedXMLText);
            XmlDocument signedXML = new XmlDocument();
            X509Certificate2 signingCert = GetCertificateFromFilePath("SelfSignedTestCert.pfx");
            //X509Certificate2 signingCert = GetCertificateBySubject("CN=TestSignCert", StoreName.My, StoreLocation.CurrentUser);
            signedXML = SignSoapBody(unsignedXML, signingCert);

            return signedXML.OuterXml;
        }

        /// <summary>
        /// Retrieve a Certificate from the Windows Certificate store
        /// by its Friendly name.
        /// </summary>
        /// <param name="subject">The friendly name of the certificate</param>
        /// <param name="storeName">The store name type ( for example: Storename.My )</param>
        /// <param name="storeLocation">Top level Location (CurrentUser,LocalMachine)</param>
        /// <returns></returns>
        static X509Certificate2 GetCertificateBySubject(string subject, StoreName storeName, StoreLocation storeLocation)
        {
            X509Store xstore = new X509Store(storeName, storeLocation);
            xstore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2 cert = null;
            foreach (X509Certificate2 cert2 in xstore.Certificates)
            {
                //string sub = wwUtils.ExtractString(cert2.Subject, "CN=", ",", true, true);

                if (cert2.Subject.Contains(subject))
                {
                    cert = cert2;
                    break;
                }
            }
            return cert;
        }
        public X509Certificate2 GetCertificateFromFile(string fileName)
        {
            X509Certificate cert = X509Certificate.CreateFromCertFile(fileName);
            return new X509Certificate2(cert);
        }
        public X509Certificate2 GetCertificateFromFilePath(string fileName)
        {
            string path = @"/app/cert";// (Directory.GetCurrentDirectory());
            string certPath = path + @"/" + fileName;
            string certPass = "password";
            X509Certificate2 returnCert = new X509Certificate2();
            // Create a collection object and populate it using the PFX file
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Import(certPath, certPass, X509KeyStorageFlags.PersistKeySet);
            foreach (X509Certificate2 cert in collection)
            {
                Console.WriteLine("Subject is: '{0}'", cert.Subject);
                Console.WriteLine("Issuer is:  '{0}'", cert.Issuer);
                returnCert = cert;
            }
            return returnCert;
        }
        static XmlDocument SignSoapBody(XmlDocument xmlDoc, X509Certificate2 cert)
        {
            // *** Add search Namespaces references to ensure we can reliably work 
            // *** against any SOAP docs regardless of tag naming
            STR_SOAPSEC_NS = "http://schemas.xmlsoap.org/soap/security/2000-12";
            STR_SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
            XmlNamespaceManager ns = new XmlNamespaceManager(xmlDoc.NameTable);
            ns.AddNamespace("SOAP", STR_SOAP_NS);
            ns.AddNamespace("SOAP-SEC", STR_SOAPSEC_NS);

            // *** Grab the body element - this is what we create the signature from
            XmlElement body = xmlDoc.DocumentElement.SelectSingleNode(@"//SOAP:Body", ns) as XmlElement;
            if (body == null)
                throw new ApplicationException("No body tag found");

            // *** We'll only encode the <SOAP:Body> - add id: Reference as #Body
            body.SetAttribute("id", "Body");

            // *** Signed XML will create Xml Signature - Xml fragment
            SignedXml signedXml = new SignedXml(xmlDoc);

            // *** Create a KeyInfo structure
            KeyInfo keyInfo = new KeyInfo();

            // *** The actual key for signing - MAKE SURE THIS ISN'T NULL!
            signedXml.SigningKey = cert.PrivateKey;

            // *** Specifically use the issuer and serial number for the data rather than the default
            KeyInfoX509Data keyInfoData = new KeyInfoX509Data();
            keyInfoData.AddIssuerSerial(cert.Issuer, cert.GetSerialNumberString());
            keyInfo.AddClause(keyInfoData);


            // *** provide the certficate info that gets embedded - note this is only
            // *** for specific formatting of the message to provide the cert info
            signedXml.KeyInfo = keyInfo;


            // *** Again unusual - meant to make the document match template
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            // *** Now create reference to sign: Point at the Body element
            Reference reference = new Reference();
            reference.Uri = "#Body";  // reference id=body section in same doc
            reference.AddTransform(new XmlDsigExcC14NTransform());  // required to match doc
            signedXml.AddReference(reference);

            // *** Finally create the signature
            signedXml.ComputeSignature();

            // *** Result is an XML node with the signature detail below it
            // *** Now let's add the sucker into the SOAP-HEADER
            XmlElement signedElement = signedXml.GetXml();

            // *** Create SOAP-SEC:Signature element
            XmlElement soapSignature = xmlDoc.CreateElement("Signature", STR_SOAPSEC_NS);
            soapSignature.Prefix = "SOAP-SEC";
            soapSignature.SetAttribute("MustUnderstand", "", "1");

            // *** And add our signature as content
            soapSignature.AppendChild(signedElement);

            // *** Now add the signature header into the master header
            XmlElement soapHeader = xmlDoc.DocumentElement.SelectSingleNode("//SOAP:Header", ns) as XmlElement;
            if (soapHeader == null)
            {
                soapHeader = xmlDoc.CreateElement("Header", STR_SOAP_NS);
                soapHeader.Prefix = "SOAP";
                xmlDoc.DocumentElement.InsertBefore(soapHeader, xmlDoc.DocumentElement.ChildNodes[0]);
            }
            soapHeader.AppendChild(soapSignature);

            return xmlDoc;
        }

    }
}
