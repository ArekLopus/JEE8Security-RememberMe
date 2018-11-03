package jaxrs;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.security.enterprise.SecurityContext;
import javax.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

//-After login, in server console we can see that remember me store token is created and stored
//-In browser / tools / Application / Cookies there is a cookie JREMEMBERMEID with the token as a value
// JREMEMBERMEID | 959620ec3d304d9b5fec6d06457c8d779c10858d56aab6283588e42e149cf68d
//-Cookie is set for 20 seconds in @RememberMe so we have this time to access secured resources

//http://localhost:8080/JEE8Security-RememberMe/res/sec/secured
//http://localhost:8080/JEE8Security-RememberMe/res/sec/login
@Path("sec")
@Produces(MediaType.TEXT_HTML)
public class TestResources {
	
	@Inject
	SecurityContext sc;
	
	@Context
	HttpServletRequest request;
	
	@Context
	HttpServletResponse response;
	
	@Path("login")
	@GET
	public String testLogin() {
		
		UsernamePasswordCredential credentials = new UsernamePasswordCredential("aa", "aa");
		
		AuthenticationParameters params = AuthenticationParameters.withParams().credential(credentials);
		params.setRememberMe(true);
		
		sc.authenticate(request, response, params);
		
		if(sc.getCallerPrincipal() == null) {
			return "Principal NULL";
		}
		String info = "Session: "+ request.getSession(false) 
				+ "<br/>User: " + sc.getCallerPrincipal().getName()
				+ "<br/>is caller in role 'admin' -> "+sc.isCallerInRole("admin")
				+ "<br/>is caller in role 'user' -> "+sc.isCallerInRole("user");
		
		return info;
	}
	
	@RolesAllowed("admin")
	@Path("secured")
	@GET
	public String testSecured() throws ServletException {
		
		if(sc.getCallerPrincipal() == null) {
			return "Principal NULL";
		}
		String info = "Session: "+ request.getSession(false)
				+ "<br/>User: " + sc.getCallerPrincipal().getName()
				+ "<br/>is caller in role 'admin' -> "+sc.isCallerInRole("admin")
				+ "<br/>is caller in role 'user' -> "+sc.isCallerInRole("user");
		
		return info;
	}
	
}
