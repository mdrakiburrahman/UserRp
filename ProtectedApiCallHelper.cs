﻿// Copyright (c) Microsoft Corporation. All rights reserved.
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
        /// <param name="token">Pre-formatted header token</param>
        public async Task<JsonNode> CallWebApiAndProcessResultASync(
            HttpRequestMessage request,
            string token
        )
        {
            if (token != null)
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
                if (defaultRequestHeaders.Authorization == null)
                {
                    defaultRequestHeaders.Add("Authorization", token);
                }

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

                    // Note that if you got reponse.Code == 403 and response.content.code == "Authorization_RequestDenied"
                    // this is because the tenant admin as not granted consent for the application to call the Web API
                    Console.WriteLine($"Content: {content}");
                }
                Console.ResetColor();
            }

            return null;
        }
    }
}
