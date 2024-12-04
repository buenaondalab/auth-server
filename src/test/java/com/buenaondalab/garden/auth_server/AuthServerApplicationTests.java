package com.buenaondalab.garden.auth_server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.htmlunit.Page;
import org.htmlunit.WebClient;
import org.htmlunit.WebResponse;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlCheckBoxInput;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"spring.profiles.include=test"})
@AutoConfigureMockMvc
class AuthServerApplicationTests {

	@Value("${spring.security.user.name}")
	String username;
	@Value("${spring.security.user.password}")
	String password;
	// @Value("${garden.oauth2.clients.0}")
	String clientId = "gateway";

	private final String redirectUri = "http://localhost:8080/"+clientId+"/login/oauth2/code/"+clientId;

	private final String authorizationRequest = UriComponentsBuilder
			.fromPath("/oauth2/authorize")
			.queryParam("response_type", "code")
			.queryParam("client_id", clientId)
			.queryParam("scope", "openid")
			.queryParam("state", "some-state")
			.queryParam("redirect_uri", redirectUri)
			.toUriString();

	private final String consentsAuthRequest = UriComponentsBuilder
			.fromUriString(authorizationRequest)
			.replaceQueryParam("scope", "openid catalog.read catalog.write")
			.toUriString();

	@Autowired
	private WebClient webClient;

	@MockitoBean
	private OAuth2AuthorizationConsentService authorizationConsentService;

	@BeforeEach
	public void setUp() {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
		this.webClient.getOptions().setRedirectEnabled(true);
		this.webClient.getCookieManager().clearCookies();	// log out
		when(this.authorizationConsentService.findById(any(), any())).thenReturn(null);
	}

	@Test
	public void whenLoginSuccessfulThenDisplayNotFoundError() throws IOException {
		HtmlPage page = this.webClient.getPage("/");

		assertLoginPage(page);

		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		WebResponse signInResponse = signIn(page, username, password).getWebResponse();
		assertThat(signInResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND.value());	// there is no "default" index page
	}

	@Test
	public void whenLoginFailsThenDisplayBadCredentials() throws IOException {
		HtmlPage page = this.webClient.getPage("/");

		HtmlPage loginErrorPage = signIn(page, username, "wrong-password");

		HtmlElement alert = loginErrorPage.querySelector("div[role=\"alert\"]");
		assertThat(alert).isNotNull();
		assertThat(alert.getTextContent()).isEqualTo("Bad credentials");
	}

	@Test
	public void whenNotLoggedInAndRequestingTokenThenRedirectsToLogin() throws IOException {
		HtmlPage page = this.webClient.getPage(authorizationRequest);

		assertLoginPage(page);
	}

	@Test
	public void whenLoggingInAndRequestingTokenThenRedirectsToClientApplication() throws IOException {
		// Log in
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		this.webClient.getOptions().setRedirectEnabled(false);
		signIn(this.webClient.getPage("/login"), username, password);

		// Request token
		WebResponse response = this.webClient.getPage(authorizationRequest).getWebResponse();

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());
		String location = response.getResponseHeaderValue("location");
		assertThat(location).startsWith(redirectUri);
		assertThat(location).contains("code=");
	}

	@Test
	@DisplayName("OpenID Provider Configuration Endpoint is available")
	public void openIDconfig(){
		assertDoesNotThrow(() -> this.webClient.getPage("/.well-known/openid-configuration"));
	}

	@Test
	@WithMockUser("test")
	public void whenUserConsentsToAllScopesThenReturnAuthorizationCode() throws IOException {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		final HtmlPage consentPage = this.webClient.getPage(consentsAuthRequest);
		assertThat(consentPage.getTitleText()).isEqualTo("Consent required");

		List<HtmlCheckBoxInput> scopes = new ArrayList<>();
		consentPage.querySelectorAll("input[name='scope']").forEach(scope ->
				scopes.add((HtmlCheckBoxInput) scope));
		for (HtmlCheckBoxInput scope : scopes) {
			scope.click();
		}

		List<String> scopeIds = new ArrayList<>();
		scopes.forEach(scope -> {
			assertThat(scope.isChecked()).isTrue();
			scopeIds.add(scope.getId());
		});
		assertThat(scopeIds).containsExactlyInAnyOrder("catalog.read", "catalog.write");

		DomElement submitConsentButton = consentPage.querySelector("button[id='submit-consent']");
		this.webClient.getOptions().setRedirectEnabled(false);

		WebResponse approveConsentResponse = submitConsentButton.click().getWebResponse();
		assertThat(approveConsentResponse.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());
		String location = approveConsentResponse.getResponseHeaderValue("location");
		assertThat(location).startsWith(redirectUri);
		assertThat(location).contains("code=");
	}

	@Test
	@WithMockUser("test")
	public void whenUserCancelsConsentThenReturnAccessDeniedError() throws IOException {
		this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
		final HtmlPage consentPage = this.webClient.getPage(consentsAuthRequest);
		assertThat(consentPage.getTitleText()).isEqualTo("Consent required");

		DomElement cancelConsentButton = consentPage.querySelector("button[id='cancel-consent']");
		this.webClient.getOptions().setRedirectEnabled(false);

		WebResponse cancelConsentResponse = cancelConsentButton.click().getWebResponse();
		assertThat(cancelConsentResponse.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());
		String location = cancelConsentResponse.getResponseHeaderValue("location");
		assertThat(location).startsWith(redirectUri);
		assertThat(location).contains("error=access_denied");
	}

	private static <P extends Page> P signIn(HtmlPage page, String username, String password) throws IOException {
		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		usernameInput.type(username);
		passwordInput.type(password);
		return signInButton.click();
	}

	private static void assertLoginPage(HtmlPage page) {
		assertThat(page.getUrl().toString()).endsWith("/login");

		HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
		HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
		HtmlButton signInButton = page.querySelector("button");

		assertThat(usernameInput).isNotNull();
		assertThat(passwordInput).isNotNull();
		assertThat(signInButton.getTextContent()).isEqualTo("Sign in");
	}

}
