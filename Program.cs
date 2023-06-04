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
using System.Diagnostics;
using System.IO;

/*
 *
 ██ ██ █████  █████  █████████  ██████████ ███████████      ███████████   ███████████  ██ ██
░██░██░░███  ░░███  ███░░░░░███░░███░░░░░█░░███░░░░░███    ░░███░░░░░███ ░░███░░░░░███░██░██
░░ ░░  ░███   ░███ ░███    ░░░  ░███  █ ░  ░███    ░███     ░███    ░███  ░███    ░███░░ ░░
       ░███   ░███ ░░█████████  ░██████    ░██████████      ░██████████   ░██████████
       ░███   ░███  ░░░░░░░░███ ░███░░█    ░███░░░░░███     ░███░░░░░███  ░███░░░░░░
       ░███   ░███  ███    ░███ ░███ ░   █ ░███    ░███     ░███    ░███  ░███
       ░░████████  ░░█████████  ██████████ █████   █████    █████   █████ █████
        ░░░░░░░░    ░░░░░░░░░  ░░░░░░░░░░ ░░░░░   ░░░░░    ░░░░░   ░░░░░ ░░░░░
*
*/

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
        private const string HybridConnectivityManagementEndpoint =
            @"https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.HybridCompute/machines/{2}/providers/Microsoft.HybridConnectivity/endpoints/default/listCredentials?api-version={3}";

        /// <summary>
        /// Arc Server Resource ID
        /// </summary>
        private const string ArcServerResourceId =
            @"/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.HybridCompute/machines/{2}";

        /// <summary>
        /// SNI Proxy URI
        /// </summary>
        private const string SniProxyEndpoint =
            "http://localhost:47010/sni/register?api-version=2022-05-01";

        /// <summary>
        /// Management Endpoint
        /// </summary>
        private const string ManagementEndpoint = "https://management.azure.com";

        /// <summary>
        /// Policy Administration Service Endpoint for AuthZ/RBAC
        /// </summary>
        private const string PasEndpoint = "https://pas.windows.net";

        /// <summary>
        /// The Arc Data authorization header has "POP;PAS| tag instead of the usual "Bearer".
        /// </summary>
        public const string PoPPasTokenTag = "POP;PAS|";

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
            // Get config from file
            //
            AuthenticationConfig config = AuthenticationConfig.ReadFromJsonFile("appsettings.json");

            // Start Proxy once - required for local debugging
            //
            string binaryPath = Path.Combine(config.PathToProxy, "sniproxy.exe");
            string configPath = Path.Combine(config.PathToProxy, "sniproxy.conf");
            string arguments = $"-c {configPath}";
            await StartProcessAsync(binaryPath, arguments);

            // This will keep on generating new Relay URLs upon expiry, and trying again
            //
            while (true)
            {
                try
                {
                    // Generate Relay URL from SNI Proxy
                    //
                    JObject proxyUrlObject = await GetRelayUrlAsync(config);
                    string fullUri = proxyUrlObject["proxy"].ToString();
                    int expiresOn = (int)proxyUrlObject["expiresOn"];

                    // Dotnet cannot use localhost subdomains, so we must trim out the host header SNI Proxy expects
                    //
                    var hostHeader = fullUri.Split('/')[2].Split(':')[0];
                    var port = fullUri.Split('/')[2].Split(':')[1];

                    Console.WriteLine($"--------------------------------------");
                    Console.WriteLine($"Full URI: {fullUri}");
                    Console.WriteLine($"Host Header: {hostHeader}");
                    Console.WriteLine($"Port: {port}");
                    Console.WriteLine($"Expires On: {expiresOn}");
                    Console.WriteLine($"--------------------------------------");

                    // Token: PoP Token - for Extension API AuthN
                    //
                    // If you look in the JWT, PoP Tokens do not have an aud
                    // field, this is only included just for MSAL SDK syntax.
                    // The actual validation of the PoP Token will be done by
                    // Extension API by validating individual PoP specific
                    // fields.
                    //
                    AuthenticationResult PopResult = await GetOAuthToken(
                        config,
                        new string[] { $"https://localhost/.default" },
                        true,
                        config.ArceeApiUrl,
                        "GET"
                    );

                    // Token: PAS Token - for Extension side RBAC
                    //
                    AuthenticationResult PasResult = await GetOAuthToken(
                        config,
                        new string[] { $"{PasEndpoint}/.default" },
                        false,
                        "",
                        ""
                    );

                    if (PopResult != null && PasResult != null)
                    {
                        // Construct PoP + PaS token
                        //
                        string popPasToken =
                            $"{PoPPasTokenTag}POP {PopResult.AccessToken}{";"}PAS {PasResult.AccessToken}";

                        // SSL validation - checks the certificate is from our Arc Server
                        //
                        var handler = new HttpClientHandler()
                        {
                            ServerCertificateCustomValidationCallback = (
                                sender,
                                cert,
                                chain,
                                sslPolicyErrors
                            ) =>
                            {
                                if (cert != null && cert.SubjectName.Name != null)
                                {
                                    var receivedCommonName = cert.SubjectName.Name
                                        .Split('=')
                                        .LastOrDefault()
                                        ?.Trim();
                                    string expectedCommonName = string.Format(
                                        ArcServerResourceId,
                                        config.SubscriptionId,
                                        config.ResourceGroup,
                                        config.ArcServerName
                                    );
                                    if (receivedCommonName == expectedCommonName)
                                    {
                                        // We're talking to Arcee Extension API
                                        //
                                        return true;
                                    }
                                }
                                // The certificate is not what we expected - do not allow the call to proceed
                                //
                                return false;
                            }
                        };
                        var httpClient = new HttpClient(handler);
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
                            // Construct new request object, these cannot be reused
                            var request = new HttpRequestMessage(
                                HttpMethod.Get,
                                $"https://localhost:{port}"
                            );
                            request.Headers.Host = hostHeader;

                            // Send GET request to the API endpoint and get the JSON payload
                            var apiResult = await apiCaller.CallWebApiAndProcessResultASync(
                                request,
                                popPasToken
                            );

                            // Calculate the elapsed time for each API call
                            var elapsed_time = (DateTime.Now - start_time).TotalSeconds;

                            // Calculate the queries per second (QPS) and update the rolling average
                            var qps = 1 / elapsed_time;
                            total_qps = (total_qps * num_queries + qps) / (num_queries + 1);
                            num_queries += 1;

                            // Calculate time remaining on the Relay URL
                            var timeRemainingSeconds =
                                expiresOn - DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                            // Print the rolling average QPS, server name, and server time
                            var statistics =
                                $"[Proxy refresh in: {timeRemainingSeconds} s] Query: {num_queries}: Average QPS = {total_qps} queries/second";

                            // =================== Random SQL Query ===================
                            /*
                            JsonArray nodes = apiResult.AsArray();
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
                            */
                            // =================== Random SQL Query ===================
                            // =================== GET sqlServerInstance ===================
                            string nameKey = "name";
                            statistics += $" | {nameKey}: {apiResult[nameKey]?.ToString()}";
                            // =================== GET sqlServerInstance ===================
                            Console.WriteLine(statistics);

                            // Reset the start time for the next API call
                            start_time = DateTime.Now;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("============ MESSAGE ===========");
                    Console.WriteLine(ex.Message);
                    Console.WriteLine();
                    Console.WriteLine("============ INNER EXCEPTION ===========");
                    Console.WriteLine(ex.InnerException);
                    Console.WriteLine();
                    Console.WriteLine("============ STACK TRACE ===========");
                    Console.WriteLine(ex.StackTrace);
                    Console.WriteLine();
                    Console.ResetColor();
                }
            }
        }

        /// <summary>
        /// Generates a new Relay URL from the local SNI Proxy and returns it:
        ///
        ///  e.g. "https://0fba8dc65ef4edcbfc83717a269dd5bc.localhost:8443"
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
            httpClientHandler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            var httpClient = new HttpClient(httpClientHandler);

            // Token: Management Endpoint - for getting Relay Credentials, not
            // being sent to Extension
            //
            AuthenticationResult result = await GetOAuthToken(
                config,
                new string[] { $"{ManagementEndpoint}/.default" },
                false,
                "",
                ""
            );

            // Get new Relay Credentials
            string requestUrl = string.Format(
                HybridConnectivityManagementEndpoint,
                SubscriptionId,
                ResourceGroup,
                ArcServerName,
                HybridConnectivityApiVersion
            );
            var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer",
                result.AccessToken
            );
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
                serviceConfig = new ServiceConfig { service = ArceeApiUrl, hostname = "localhost" },
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
            request.Content = new StringContent(
                sniRequestBodyJson,
                Encoding.UTF8,
                "application/json"
            );
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
        /// Returns a Proof-of-Possesion (PoP) OAuth token for the specified scopes and url.
        /// </summary>
        private static async Task<AuthenticationResult> GetOAuthToken(
            AuthenticationConfig config,
            string[] scopes,
            bool PoPNeeded,
            string host,
            string verb = ""
        )
        {
            // The application is a confidential client application
            //
            IConfidentialClientApplication app;

            app = ConfidentialClientApplicationBuilder
                .Create(config.ClientId)
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
                    PoPAuthenticationConfiguration popConfig = new PoPAuthenticationConfiguration(
                        new Uri(host)
                    );
                    popConfig.Nonce = "nonce";

                    // TODO: Configure other best practices, see:
                    //
                    // - https://msazure.visualstudio.com/One/_git/compute-hybridrp?path=/src/Shared/Common/Utilities/AuthenticationClient.cs&version=GBmaster
                    // - https://msazure.visualstudio.com/One/_git/compute-GuestNotificationServiceDP?path=/src/Microsoft.Arc.Notifications.Common/TokenProvider/PoPTokenProvider.cs&version=GBmaster
                    //

                    switch (verb.ToUpper())
                    {
                        case "GET":
                            popConfig.HttpMethod = HttpMethod.Get;
                            break;
                        case "POST":
                            popConfig.HttpMethod = HttpMethod.Post;
                            break;
                        case "PUT":
                            popConfig.HttpMethod = HttpMethod.Put;
                            break;
                        case "DELETE":
                            popConfig.HttpMethod = HttpMethod.Delete;
                            break;
                        case "PATCH":
                            popConfig.HttpMethod = HttpMethod.Patch;
                            break;
                        default:
                            popConfig.HttpMethod = HttpMethod.Get;
                            break;
                    }

                    result = await app.AcquireTokenForClient(scopes)
                        .WithProofOfPossession(popConfig)
                        .ExecuteAsync()
                        .ConfigureAwait(false);
                }
                else
                {
                    result = await app.AcquireTokenForClient(scopes)
                        .ExecuteAsync()
                        .ConfigureAwait(false);
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

        /// <summary>
        /// Start a process async with arguments.
        /// </summary>
        static async Task StartProcessAsync(string binaryPath, string arguments)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo(binaryPath, arguments);
            startInfo.UseShellExecute = false;

            Process process = new Process();
            process.StartInfo = startInfo;
            process.Start();
        }
    }
}
