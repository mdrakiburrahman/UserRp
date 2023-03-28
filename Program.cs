// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure.Core;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;
using Microsoft.Identity.Web;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace UserArrP
{
    /// <summary>
    /// This sample shows how to query the Microsoft Graph from a daemon application
    /// which uses application permissions.
    /// For more information see https://aka.ms/msal-net-client-credentials
    /// </summary>
    class Program
    {
        /// <summary>
        /// Microsoft.HybridConnectivity API version
        /// </summary>
        private const string HybridConnectivityApiVersion = "2021-10-06-preview";

        /// <summary>
        /// Microsoft.HybridConnectivity Management URI
        /// </summary>
        private const string HybridConnectivityManagementEndpoint = @"https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.HybridCompute/machines/{2}/providers/Microsoft.HybridConnectivity/endpoints/default/listCredentials?api-version={3}";

        /// <summary>
        /// SNI Proxy URI
        /// </summary>
        private const string SniProxyEndpoint = @"https://control.{0}.arc.wac.azure.com:47011/sni/register?api-version=2022-05-01";

        /// <summary>
        /// Arc Server Hostname FQDN format
        /// </summary>
        private const string ArcServerHostNameFqdn = @"{0}.{1}.arc.waconazure.com";

        /// <summary>
        /// Management Endpoint
        /// </summary>
        private const string ManagementEndpoint = "https://management.azure.com";

        /// <summary>
        /// Main entrypoint.
        /// </summary>
        static void Main(string[] args)
        {
            try
            {
                RunAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();
            }

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        /// <summary>
        /// Infinite loop at runtime
        /// </summary>
        private static async Task RunAsync()
        {
            // This will keep on generating new Relay URLs upon expiry, and trying again
            //
            while (true)
            {
                try
                {
                    AuthenticationConfig config = AuthenticationConfig.ReadFromJsonFile("appsettings.json");

                    JObject proxyUrlObject = await GetRelayUrlAsync(config);
                    string popUri = proxyUrlObject["proxy"].ToString();
                    int expiresOn = (int)proxyUrlObject["expiresOn"];

                    // This is basically the Client ID of the specific Arc Server, visible in AAD:
                    //
                    // - https://ms.portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/c579b537-d28b-491a-98b0-fccd193c2d05/appId/5fa47195-e890-485e-a90c-3d417cfcb1e2
                    //   e.g. "5fa47195-e890-485e-a90c-3d417cfcb1e2/.default"
                    //   
                    string[] scopes = new string[] { $"{config.ArcServerClientId}/.default" };

                    AuthenticationResult result = await GetOAuthToken(config, scopes, true, popUri);

                    if (result != null)
                    {
                        var httpClient = new HttpClient();
                        var apiCaller = new ProtectedApiCallHelper(httpClient);

                        // Benchmark
                        //
                        double total_qps = 0;
                        int num_queries = 0;
                        var start_time = DateTime.Now;

                        // This will keep on looping until the Relay URL expires, and then throw
                        //
                        while (true)
                        {
                            // Send GET request to the API endpoint and get the JSON payload
                            var apiResult = await apiCaller.CallWebApiAndProcessResultASync(popUri, result);

                            // Calculate the elapsed time for each API call
                            var elapsed_time = (DateTime.Now - start_time).TotalSeconds;

                            // Calculate the queries per second (QPS) and update the rolling average
                            var qps = 1 / elapsed_time;
                            total_qps = (total_qps * num_queries + qps) / (num_queries + 1);
                            num_queries += 1;

                            // Calculate time remaining on the Relay URL
                            var timeRemainingSeconds = expiresOn - DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                            // Print the rolling average QPS, server name, and server time
                            JsonArray nodes = apiResult.AsArray();
                            var statistics = $"[Proxy refresh in: {timeRemainingSeconds} s] Query: {num_queries}: Average QPS = {total_qps} queries/second";

                            foreach (JsonObject aNode in nodes.ToArray().Cast<JsonObject>())
                            {
                                foreach (var property in aNode.ToArray())
                                {
                                    if (property.Key == "Server Name" || property.Key == "Server Time")
                                    {

                                        statistics += $" | {property.Key}: {property.Value?.ToString()}";
                                    }
                                }
                            }
                            Console.WriteLine(statistics);

                            // Reset the start time for the next API call
                            start_time = DateTime.Now;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(ex.Message);
                    Console.ResetColor();
                }
            }
        }

        /// <summary>
        /// Generates a new Relay URL and returns it:
        ///
        ///  e.g. "https://68d3eb8a77c95a7acf97c4d61c0fe84e.c579b537-d28b-491a-98b0-fccd193c2d05.eastus.arc.waconazure.com:6443"
        ///
        /// </summary>
        private static async Task<JObject> GetRelayUrlAsync(AuthenticationConfig config)
        {
            var SubscriptionId = config.SubscriptionId;
            var ResourceGroup = config.ResourceGroup;
            var ArcServerName = config.ArcServerName;
            var ArcServerLocation = config.ArcServerLocation;
            var ArceeApiUrl = config.ArceeApiUrl;
            var ArcServerprincipalId = config.ArcServerprincipalId;

            // Turn off SSL validation on the HttpClient, for the SNI Proxy which will be local in our case
            var httpClientHandler = new HttpClientHandler();
            httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            var httpClient = new HttpClient(httpClientHandler);            

            // Get token against Management Endpoint
            string[] scopes = new string[] { $"{ManagementEndpoint}/.default" };
            AuthenticationResult result = await GetOAuthToken(config, scopes, false, "");

            // Get new Relay Credentials
            string requestUrl = string.Format(HybridConnectivityManagementEndpoint, SubscriptionId, ResourceGroup, ArcServerName, HybridConnectivityApiVersion);
            var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            request.Content = new StringContent(string.Empty, Encoding.UTF8, "application/json");
            var response = await httpClient.SendAsync(request);
            string responseContent = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                throw new Exception($"Error getting Relay Credentials: {responseContent}");
            }

            // Build up request body
            var relayJObject = JsonConvert.DeserializeObject<JObject>(responseContent)["relay"];
            var sniRequestBody = new SniRequestBody
            {
                serviceConfig = new ServiceConfig
                {
                    service = ArceeApiUrl,
                    hostname = string.Format(ArcServerHostNameFqdn, ArcServerprincipalId, ArcServerLocation)
                },
                relay = new Relay
                {
                    namespaceName = relayJObject["namespaceName"].ToString(),
                    namespaceNameSuffix = relayJObject["namespaceNameSuffix"].ToString(),
                    hybridConnectionName = relayJObject["hybridConnectionName"].ToString(),
                    accessKey = relayJObject["accessKey"].ToString(),
                    expiresOn = (int)relayJObject["expiresOn"]
                }
            };
            var sniRequestBodyJson = JsonConvert.SerializeObject(sniRequestBody);

            // Get new Relay URL
            requestUrl = string.Format(SniProxyEndpoint, ArcServerLocation);
            request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            request.Content = new StringContent(sniRequestBodyJson, Encoding.UTF8, "application/json");
            try
            {
                response = await httpClient.SendAsync(request);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw new Exception($"Error getting Relay URL from Credentials: {ex.Message}");
            }
            
            responseContent = await response.Content.ReadAsStringAsync();
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                throw new Exception($"Error getting Relay URL from Credentials: {responseContent}");
            }
            return JsonConvert.DeserializeObject<JObject>(responseContent);
        }

        /// <summary>
        /// SNI Request body payload.
        /// </summary>
        public class SniRequestBody
        {
            public ServiceConfig serviceConfig { get; set; }
            public Relay relay { get; set; }
        }

        public class ServiceConfig
        {
            public string service { get; set; }
            public string hostname { get; set; }
        }

        public class Relay
        {
            public string namespaceName { get; set; }
            public string namespaceNameSuffix { get; set; }
            public string hybridConnectionName { get; set; }
            public string accessKey { get; set; }
            public int expiresOn { get; set; }
        }

        /// <summary>
        /// Returns an OAuth token for the specified scopes.
        /// </summary>
        private static async Task<AuthenticationResult> GetOAuthToken(AuthenticationConfig config, string[] scopes, bool PoPNeeded, string popUri)
        {
            // The application is a confidential client application
            //
            IConfidentialClientApplication app;

            app = ConfidentialClientApplicationBuilder.Create(config.ClientId)
                    .WithClientSecret(config.ClientSecret)
                    .WithAuthority(new Uri(config.Authority))
                    .WithExperimentalFeatures() // for PoP
                    .Build();

            app = ConfidentialClientApplicationBuilder.Create(config.ClientId)
                .WithClientSecret(config.ClientSecret)
                .WithAuthority(new Uri(config.Authority))
                .WithExperimentalFeatures() // for PoP
                .Build();

            app.AddInMemoryTokenCache();

            AuthenticationResult result = null;
            try
            {
                if (PoPNeeded)
                {
                    result = await app.AcquireTokenForClient(scopes)
                        .WithProofOfPossession(new PoPAuthenticationConfiguration(new Uri(popUri)) { HttpMethod = HttpMethod.Get })
                        .ExecuteAsync();
                }
                else
                {
                    result = await app.AcquireTokenForClient(scopes)
                        .ExecuteAsync();
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"New Token acquired.\n");
                Console.ResetColor();
            }
            catch (MsalServiceException ex)
            {
                // Invalid scope. The scope has to be of the form "https://resourceurl/.default"
                // Mitigation: change the scope to be as expected
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();
            }
            return result;
        }
    }
}
