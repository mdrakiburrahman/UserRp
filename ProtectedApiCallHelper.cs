// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace UserArrP
{
    /// <summary>
    /// Helper class to call a protected API and process its result
    /// </summary>
    public class ProtectedApiCallHelper
    {
        /// <summary>
        /// POP Token header
        /// </summary>
        private const string popHeader = "Authorization-POP";

        /// <summary>
        /// PAS Token header
        /// </summary>
        private const string pasHeader = "Authorization-PAS";

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="httpClient">HttpClient used to call the protected API</param>
        public ProtectedApiCallHelper(HttpClient httpClient)
        {
            HttpClient = httpClient;
        }

        protected HttpClient HttpClient { get; private set; }

        /// <summary>
        /// Calls the protected web API and processes the result
        /// </summary>
        /// <param name="request">Request Object</param>
        /// <param name="popToken">Proof of possession token</param>
        /// <param name="pasToken">Policy Administration Service token</param>
        public async Task<JsonNode> CallWebApiAndProcessResultASync(
            HttpRequestMessage request,
            string popToken,
            string pasToken
        )
        {
            if (popToken != null && pasToken != null)
            {
                var defaultRequestHeaders = HttpClient.DefaultRequestHeaders;
                if (
                    defaultRequestHeaders.Accept == null
                    || !defaultRequestHeaders.Accept.Any(m => m.MediaType == "application/json")
                )
                {
                    HttpClient.DefaultRequestHeaders.Accept.Add(
                        new MediaTypeWithQualityHeaderValue("application/json")
                    );
                }

                if (!defaultRequestHeaders.Contains(popHeader)) defaultRequestHeaders.Add(popHeader, popToken);
                if (!defaultRequestHeaders.Contains(pasHeader)) defaultRequestHeaders.Add(pasHeader, pasToken);

                HttpResponseMessage response = await HttpClient.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    string json = await response.Content.ReadAsStringAsync();
                    JsonNode apiResult = JsonNode.Parse(json);
                    Console.ForegroundColor = ConsoleColor.Gray;
                    return apiResult;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Failed to call the Web Api: {response.StatusCode}");
                    string content = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Content: {content}");
                }
                Console.ResetColor();
            }

            return null;
        }
    }
}
