package com.goit.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.NoArgsConstructor;
import lombok.Value;


@Value
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class OMDBResponse {
    @JsonProperty("BoxOffice")
    String boxOffice = null;
    @JsonProperty("Response")
    String response = null;
    @JsonProperty("Error")
    String error = null;
}
