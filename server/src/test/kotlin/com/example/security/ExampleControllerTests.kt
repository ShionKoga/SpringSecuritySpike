package com.example.security

import com.example.security.controller.ExampleController
import com.example.security.controller.ExampleService
import org.hamcrest.CoreMatchers.equalTo
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder


@SpringBootTest
class ExampleControllerTests {
    @Autowired
    private lateinit var springSecurityFilterChain: FilterChainProxy

    @Nested
    inner class Hello {
        @Test
        fun `when user not authenticated then unauthorized`() {
            val dummyExampleService = DummyExampleService()
            val mockMvc = MockMvcBuilders
                .standaloneSetup(ExampleController(dummyExampleService))
                .apply<StandaloneMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity(springSecurityFilterChain))
                .build()


            val result = mockMvc.get("/example/hello")


            result.andExpect { status { isUnauthorized() } }
        }

        @Test
        @WithMockUser(username = "John")
        fun `passes username to service`() {
            val spyExampleService = SpyExampleService()
            val mockMvc = MockMvcBuilders
                .standaloneSetup(ExampleController(spyExampleService))
                .apply<StandaloneMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity(springSecurityFilterChain))
                .build()


            mockMvc.get("/example/hello")


            assertEquals("John", spyExampleService.getGreeting_argument_username)
        }

        @Test
        @WithMockUser(username = "")
        fun `returns string that service returns`() {
            val stubExampleService = StubExampleService()
            stubExampleService.getGreeting_returnValue = "greeting"
            val mockMvc = MockMvcBuilders
                .standaloneSetup(ExampleController(stubExampleService))
                .apply<StandaloneMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity(springSecurityFilterChain))
                .build()


            val result = mockMvc.perform(
                MockMvcRequestBuilders.get("/example/hello")
            )


            result
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", equalTo("greeting")))
        }

    }

	@Nested
	inner class Hoge {
		@Test
		fun `can request without authentication`() {
			val dummyExampleService = DummyExampleService()
			val mockMvc = MockMvcBuilders
				.standaloneSetup(ExampleController(dummyExampleService))
				.apply<StandaloneMockMvcBuilder>(SecurityMockMvcConfigurers.springSecurity(springSecurityFilterChain))
				.build()


			val result = mockMvc.perform(
				MockMvcRequestBuilders.get("/example/hoge")
			)


			result.andExpect(status().isOk)
			result.andExpect(jsonPath("$", equalTo("hoge")))
		}
	}
}

class SpyExampleService : ExampleService {
    var getGreeting_argument_username: String? = null
    override fun getGreeting(username: String): String {
        getGreeting_argument_username = username
        return ""
    }
}

class StubExampleService : ExampleService {
    var getGreeting_returnValue: String = ""
    override fun getGreeting(username: String): String {
        return getGreeting_returnValue
    }
}

class DummyExampleService : ExampleService {
    override fun getGreeting(username: String): String {
        return ""
    }
}
