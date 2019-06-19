package org.wso2.apim.kerberos.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.ietf.jgss.GSSManager;
import org.wso2.apim.kerberos.handler.exception.KerberosPermissionException;
import org.wso2.apim.kerberos.handler.processor.KerberosDelegationProcessor;
import org.wso2.apim.kerberos.handler.processor.KerberosTrustProcessor;
import org.wso2.apim.kerberos.handler.model.User;
import org.wso2.apim.kerberos.handler.utils.KerberosConstants;
import org.wso2.apim.kerberos.handler.utils.KerberosUtils;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.login.Configuration;

public class KerberosAuthenticationHandler  extends AbstractHandler {

    private static final Log log =
            LogFactory.getLog(KerberosAuthenticationHandler.class);
    private static final boolean kerberosDebugLogEnabled =
            Boolean.parseBoolean(System.getProperty("debug", "false"));
    private static final boolean isDebugEnabled = log.isDebugEnabled();

    private String jaasConfigPath =
            Paths.get(CarbonUtils.getCarbonSecurityConfigDirPath(),
            KerberosConstants.KERBEROS_CONF_FOLDER_NAME,
            KerberosConstants.LOGIN_CONF_FILE_NAME).toString();
    private String krb5ConfigPath =
            Paths.get(CarbonUtils.getCarbonSecurityConfigDirPath(),
            KerberosConstants.KERBEROS_CONF_FOLDER_NAME,
            KerberosConstants.KERBEROS_CONF_FILE_NAME).toString();
    private String loginContextName =
            System.getProperty(KerberosConstants.LOGIN_CONTEXT_NAME,
                    "KrbLogin");

    private String targetSPN;
    private String authenticationMode;

    @Override
    public boolean handleRequest(MessageContext messageContext) {

        Map headers = KerberosUtils.getTransportHeaders(messageContext);
        if( KerberosConstants.AUTHENTICATION_MODE_DELEGATION.equalsIgnoreCase(getAuthenticationMode())){
            if (KerberosUtils.getKerberosHeader(headers) == null) {
                return KerberosUtils.setAsUnAuthorizedUser(headers,
                        messageContext, null);
            }
        }

        if(kerberosDebugLogEnabled || isDebugEnabled){
            printDebugInformation();
        }

        String currentLoginConfPath =
                System.getProperty(KerberosConstants.LOGIN_CONFIG_PROPERTY);
        String currentKrb5ConfPath =
                System.getProperty(KerberosConstants.KERBEROS_CONFIG_PROPERTY);

        resetKerberosConfiguration();

        User user = new User();
        try {
            user.login(this.loginContextName);

            if(user.isLoggedin()){
                byte[] serviceTicket = new byte[0];

                try{
                    if( KerberosConstants.AUTHENTICATION_MODE_DELEGATION.equalsIgnoreCase(getAuthenticationMode())){
                        serviceTicket = getDelegatedTicket(user, headers);
                    } else {
                        serviceTicket = getTrustedTicket(user);
                    }
                    KerberosUtils.setKerberosTokenToHeader((Axis2MessageContext) messageContext,
                            serviceTicket);
                    return true;
                } catch (KerberosPermissionException e){
                    //Failed - no need to handle
                } catch (UnsupportedEncodingException e){
                    log.error("Encoding operation failed", e);
                }
            } else {
                return false;
            }
        } finally {
            user.logout();
            // Revert back to previous configs
            Configuration.setConfiguration(null);
            if (currentLoginConfPath != null) {
                System.setProperty(KerberosConstants.LOGIN_CONFIG_PROPERTY,
                        currentLoginConfPath);
            }
            if (currentKrb5ConfPath != null) {
                System.setProperty(KerberosConstants.KERBEROS_CONFIG_PROPERTY
                        , currentKrb5ConfPath);
            }
        }
        return false;
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }

    public String getAuthenticationMode() {
        return authenticationMode;
    }

    public void setAuthenticationMode(String authenticationMode) {
        this.authenticationMode = authenticationMode;
    }

    public String getTargetSPN() {
        return targetSPN;
    }

    public void setTargetSPN(String targetSPN) {
        this.targetSPN = targetSPN;
    }

    private void resetKerberosConfiguration(){
        Configuration.setConfiguration(null);
        System.setProperty(KerberosConstants.LOGIN_CONFIG_PROPERTY,
                new File(jaasConfigPath).getAbsolutePath());
        System.setProperty(KerberosConstants.KERBEROS_CONFIG_PROPERTY,
                new File(krb5ConfigPath).getAbsolutePath());
    }


    private byte[] getTrustedTicket(User user) throws KerberosPermissionException {

        log.debug("Invoking the getTrustedTicket for the principle " +
                user.getSubject().getPrincipals().toString());

        KerberosTrustProcessor kerberosTrustProcessor =
                new KerberosTrustProcessor(user.getSubject());

        return kerberosTrustProcessor.trust(this.targetSPN);
    }

    private byte[] getDelegatedTicket(User user, Map headers) throws KerberosPermissionException {

        KerberosDelegationProcessor kerberosDelegationProcessor =
                new KerberosDelegationProcessor(user.getSubject());
        String clientKerberosTicket = KerberosUtils.getKerberosHeader(headers);
        if (log.isDebugEnabled()) {
            log.debug("Acquired Client's Kerberos ticket: " + clientKerberosTicket);
            log.debug("Initiating constrained delegation for SPN: " + targetSPN);
        }
        byte[] delegatedTicket =
                kerberosDelegationProcessor.delegate(Base64.getDecoder().decode(clientKerberosTicket.split(" ")[1]), targetSPN);
        String delegatedKerberosTicket =
                Base64.getEncoder().encodeToString(delegatedTicket);
        if (log.isDebugEnabled()) {
            log.debug("Acquired delegated Kerberos ticket: " + delegatedKerberosTicket);
        }
        return delegatedTicket;

    }

    private void printDebugInformation(){

        if (kerberosDebugLogEnabled) {
            log.debug("krb5 debug logs enabled for KerberosAuthenticationHandler.");
            System.setProperty(KerberosConstants.LOGIN_CONFIG_DEBUG_PROPERTY, "true");
            System.setProperty(KerberosConstants.KERBEROS_CONFIG_DEBUG_PROPERTY, "true");
        }

        if (isDebugEnabled) {
            log.debug("Kerberos jaas.conf file path set to : " + jaasConfigPath);
            log.debug("Kerberos krb5.conf file path set to : " + krb5ConfigPath);
        }
    }


}
