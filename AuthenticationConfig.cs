using Microsoft.Extensions.Configuration;
using System;
using System.Globalization;
using System.IO;

namespace UserArrP
{
    /// <summary>
    /// Description of the configuration of an AzureAD public client application (desktop/mobile application). This should
    /// match the application registration done in the Azure portal
    /// </summary>
    public class AuthenticationConfig
    {
        /// <summary>
        /// instance of Azure AD, for example public Azure or a Sovereign cloud (Azure China, Germany, US government, etc ...)
        /// </summary>
        public string Instance { get; set; } = "https://login.microsoftonline.com/{0}";

        /// <summary>
        /// The tenant ID of the Azure AD tenant in which this application is registered (a guid
        /// </summary>
        public string TenantId { get; set; }

        /// <summary>
        /// Guid used by the application to uniquely identify itself to Azure AD
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Subscription ID of Arc Server
        /// </summary>
        public string SubscriptionId { get; set; }

        /// <summary>
        /// Resource Group of Arc Server
        /// </summary>
        public string ResourceGroup { get; set; }

        /// <summary>
        /// Name of Arc Server
        /// </summary>
        public string ArcServerName { get; set; }

        /// <summary>
        /// MSI Client ID of Arc Server
        /// </summary>
        public string UserRpClientId { get; set; }

        /// <summary>
        /// Location of Arc Server
        /// </summary>
        public string ArcServerLocation { get; set; }

        /// <summary>
        /// Location of SNIProxy and config file
        /// </summary>
        public string PathToProxy { get; set; }

        /// <summary>
        /// Arcee Extension API local endpoint
        /// </summary>
        public string ArceeApiUrl { get; set; }

        /// <summary>
        /// Generated Principal ID Arc Server
        /// </summary>
        public string ArcServerprincipalId { get; set; }

        /// <summary>
        /// URL of the authority
        /// </summary>
        public string Authority
        {
            get { return String.Format(CultureInfo.InvariantCulture, Instance, TenantId); }
        }

        /// <summary>
        /// Client secret (application password)
        /// </summary>
        /// <remarks>Daemon applications can authenticate with AAD through two mechanisms: ClientSecret
        /// (which is a kind of application password: this property)
        /// or a certificate previously shared with AzureAD during the application registration
        /// (and identified by the CertificateName property belows)
        /// <remarks>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Web Api base URL
        /// </summary>
        public string ArceeApiBaseAddress { get; set; }

        /// <summary>
        /// Reads the configuration from a json file
        /// </summary>
        /// <param name="path">Path to the configuration json file</param>
        /// <returns>AuthenticationConfig read from the json file</returns>
        public static AuthenticationConfig ReadFromJsonFile(string path)
        {
            IConfigurationRoot Configuration;

            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile(path);

            Configuration = builder.Build();
            return Configuration.Get<AuthenticationConfig>();
        }
    }
}
