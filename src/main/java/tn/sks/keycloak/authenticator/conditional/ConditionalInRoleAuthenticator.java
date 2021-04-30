package tn.sks.keycloak.authenticator.conditional;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;

public class ConditionalInRoleAuthenticator implements ConditionalAuthenticator {
    public static final ConditionalInRoleAuthenticator SINGLETON = new ConditionalInRoleAuthenticator();
    private static final Logger logger = Logger.getLogger(ConditionalInRoleAuthenticator.class);
    
    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
        
        if (user != null && authConfig != null && authConfig.getConfig() != null) {
            String skipRole = authConfig.getConfig().get(ConditionalInRoleAuthenticatorFactory.CONDITIONAL_USER_ROLE);
            RoleModel role = KeycloakModelUtils.getRoleFromString(realm, skipRole);
            if (role == null) {
                logger.errorv("Invalid role name submitted: {0}", skipRole);
                return false;
            }
            logger.warn("is user (" + user.getUsername() + ") in role: " + role.getName() + " = " + user.hasRole(role));
            logger.warn("gauth must apply: " + user.hasRole(role));
            return user.hasRole(role);
        }
        logger.warn("User or authConfig is null return false");
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        // Not user
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        // Not used
    }
    

    @Override
    public void close() {

    }
}
