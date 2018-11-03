package remember_me;

import static javax.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;

import java.security.MessageDigest;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.CallerPrincipal;
import javax.security.enterprise.credential.RememberMeCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.RememberMeIdentityStore;

@ApplicationScoped
public class TestRememberMeIdentityStore implements RememberMeIdentityStore {

    private final Map<String, CredentialValidationResult> identities = new ConcurrentHashMap<>();
    

    @Override
    public CredentialValidationResult validate(RememberMeCredential credential) {
        if (identities.containsKey(credential.getToken())) {
            return identities.get(credential.getToken());
        }

        return INVALID_RESULT;
    }

    @Override
    public String generateLoginToken(CallerPrincipal callerPrincipal, Set<String> groups) {
        
    	String token = computeDigest(callerPrincipal.getName());
    	
        //In a real world impl the data should be be stored in a DB instead of in a map.
    	//The token should be stored as a strong hash.
        identities.put(token, new CredentialValidationResult(callerPrincipal, groups));
        System.out.println("---TestRememberMeIdentityStore token added: " + token);
        System.out.println("---identities store size: " + identities.size());
        System.out.println("---identities store vals: " + identities);
        return token;
    }

    @Override
    public void removeLoginToken(String token) {
        identities.remove(token);
    }
    
    private String computeDigest(String toHash) {
    	try {
    		MessageDigest alg = MessageDigest.getInstance("SHA-256");
    		alg.reset();
    		alg.update(toHash.getBytes());
    		alg.update("someSaltingGoesHere".getBytes());
    		//alg.update(Long.toString(System.currentTimeMillis()).getBytes());
    		byte[] hash = alg.digest();
    		System.out.println("Hash: \t" + byteArrayToHex(hash));
    		return byteArrayToHex(hash);

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
    	
	}
    private String byteArrayToHex(byte[] array) {
		StringBuilder sb = new StringBuilder(array.length * 2);
		for(byte b: array)
			sb.append(String.format("%02x", b & 0xff));
		return sb.toString();
	}
}