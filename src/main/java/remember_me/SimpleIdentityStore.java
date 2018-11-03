package remember_me;

import static java.util.Arrays.asList;
import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;

import java.util.HashSet;

import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;

@ApplicationScoped
public class SimpleIdentityStore implements IdentityStore {

	public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {

        if (usernamePasswordCredential.compareTo("aa", "aa")) {
            return new CredentialValidationResult("aa", new HashSet<>(asList("admin")));
        }
        
        if (usernamePasswordCredential. compareTo("bb", "bb")) {
            return new CredentialValidationResult("bb", new HashSet<>(asList("admin", "user")));
        }

        return INVALID_RESULT;
    }

}
