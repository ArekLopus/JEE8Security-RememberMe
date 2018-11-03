package remember_me;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.authentication.mechanism.http.RememberMe;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//-No session enabled in this example
//-If session enabled runtime will first check for the authentication data in the session,
// then it will check for the remember me token and if present try the remember me identity store,
// and if that doesn't work finally try the main identity store.
@RememberMe(
	    cookieMaxAgeSeconds = 20,
	    cookieSecureOnly = false,	//for test only
	    //isRememberMeExpression ="#{self.isRememberMe(httpMessageContext)}"		//self / httpMessageContext – built in 
	    isRememberMeExpression ="#{httpMessageContext.authParameters.rememberMe}"
	)
//@AutoApplySession
@ApplicationScoped
public class CustomValidator implements HttpAuthenticationMechanism {
	
	@Inject
    private IdentityStoreHandler ish;
	
	@Override
	public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response,
			HttpMessageContext httpMessageContext) throws AuthenticationException {
		
		
		if (httpMessageContext.isAuthenticationRequest()) {
			
			Credential credential = httpMessageContext.getAuthParameters().getCredential();
			System.out.println("---- remember me: " + httpMessageContext.getAuthParameters().isRememberMe());
			
			CredentialValidationResult validate = ish.validate(credential);
			if(validate.getStatus().equals(CredentialValidationResult.Status.VALID)) {
				return httpMessageContext.notifyContainerAboutLogin(validate);
			}
			return httpMessageContext.responseUnauthorized();
		}
		
		return httpMessageContext.doNothing();
		
	}
	
	public Boolean isRememberMe(HttpMessageContext httpMessageContext) {
		return httpMessageContext.getAuthParameters().isRememberMe();
	}
}
