// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;
using Microsoft.Identity.Web;
using System;
using System.Linq;
using System.Net.Http;
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

        private static async Task RunAsync()
        {
            // This will keep on getting new URLs upon expiry, and trying again
            //
            while (true)
            {
                try
                {
                    AuthenticationConfig config = AuthenticationConfig.ReadFromJsonFile("appsettings.json");

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

                    // This is basically the Client ID of the specific Arc Server, visible in AAD:
                    //
                    // - https://ms.portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/c579b537-d28b-491a-98b0-fccd193c2d05/appId/5fa47195-e890-485e-a90c-3d417cfcb1e2
                    //   e.g. "5fa47195-e890-485e-a90c-3d417cfcb1e2/.default"
                    //   
                    string[] scopes = new string[] { config.ArcServerScope };

                    // This is the short lived Relay URL:
                    //
                    //  e.g. "https://68d3eb8a77c95a7acf97c4d61c0fe84e.c579b537-d28b-491a-98b0-fccd193c2d05.eastus.arc.waconazure.com:6443"
                    //
                    string popUri = $"{config.ArceeApiBaseAddress}";

                    AuthenticationResult result = null;
                    try
                    {
                        result = await app.AcquireTokenForClient(scopes)
                            .WithProofOfPossession(new PoPAuthenticationConfiguration(new Uri(popUri)) { HttpMethod = HttpMethod.Get })
                            .ExecuteAsync();
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Token acquired \n");
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

                            // Print the rolling average QPS, server name, and server time
                            JsonArray nodes = apiResult.AsArray();
                            var statistics = $"Query: {num_queries}: Average QPS = {total_qps} queries/second";

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
    }
}
