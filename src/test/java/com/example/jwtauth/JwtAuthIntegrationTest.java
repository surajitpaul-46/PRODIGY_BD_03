package com.example.jwtauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
public class JwtAuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    public void testAuthenticationAndRoleBasedAccessControl() throws Exception {
        // 1. Register regular user
        String userRegisterJson = """
                {
                    "username": "regular_user",
                    "email": "user@example.com",
                    "password": "userpass123",
                    "roles": ["user"]
                }
                """;
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(userRegisterJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User registered successfully!"));

        // 2. Register admin user
        String adminRegisterJson = """
                {
                    "username": "admin_user",
                    "email": "admin@example.com",
                    "password": "adminpass123",
                    "roles": ["admin"]
                }
                """;
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(adminRegisterJson))
                .andExpect(status().isOk());

        // 3. Login regular user and get JWT
        String userLoginJson = """
                {
                    "username": "regular_user",
                    "password": "userpass123"
                }
                """;
        MvcResult userLoginResult = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(userLoginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andReturn();

        String userToken = objectMapper.readTree(userLoginResult.getResponse().getContentAsString()).get("token").asText();

        // 4. Login admin user and get JWT
        String adminLoginJson = """
                {
                    "username": "admin_user",
                    "password": "adminpass123"
                }
                """;
        MvcResult adminLoginResult = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(adminLoginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andReturn();

        String adminToken = objectMapper.readTree(adminLoginResult.getResponse().getContentAsString()).get("token").asText();

        // 5. Unauthenticated request to /api/test/profile should be 401 Unauthorized
        mockMvc.perform(get("/api/test/profile"))
                .andExpect(status().isUnauthorized());

        // 6. Regular user accesses /api/test/profile -> 200 OK
        mockMvc.perform(get("/api/test/profile")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("regular_user"));

        // 7. Regular user attempts to access /api/test/admin -> 403 Forbidden
        mockMvc.perform(get("/api/test/admin")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());

        // 8. Admin user accesses /api/test/admin -> 200 OK
        mockMvc.perform(get("/api/test/admin")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // 9. Admin user accesses /api/test/users -> 200 OK
        mockMvc.perform(get("/api/test/users")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }
}
