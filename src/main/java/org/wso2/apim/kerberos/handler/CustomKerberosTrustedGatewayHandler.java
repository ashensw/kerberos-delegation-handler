package org.wso2.apim.kerberos.handler;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.wso2.apim.kerberos.handler.utils.KerberosConstants;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class CustomKerberosTrustedGatewayHandler extends AbstractHandler {

    private static final Log log =
            LogFactory.getLog(CustomKerberosTrustedGatewayHandler.class);
    public static final String CARBON_HOME = "carbon.home";
    private static final String ROOT = System.getProperty(CARBON_HOME, ".");
    public static final String DEFAULT_LOGIN_CONFIG_FILE = "login.conf";

    public static final String DEFAULT_KERBEROS_CONFIG_FILE = "krb5.conf";
    //Oid for SPENGO mechanism.
    public static final String SPNEGO_BASED_OID = "1.3.6.1.5.5.2";

    public static final String IS_INITIATOR = "isInitiator";
    public static final String PRINCIPAL = "principal";
    public static final String USE_KEYTAB = "useKeyTab";
    public static final String KEYTAB = "keyTab";
    public static final String DEBUG = "debug";
    public static final String UTF8 = "UTF-8";

    String kerberosConfPath =
            Paths.get(CarbonUtils.getCarbonSecurityConfigDirPath(),
                    KerberosConstants.KERBEROS_CONF_FOLDER_NAME).toString();
    private final String DEFAULT_LOGIN_CONFIG_FILE_PATH =
            Paths.get(kerberosConfPath, DEFAULT_LOGIN_CONFIG_FILE).toString();
    private final String DEFAULT_KERBEROS_CONFIG_PATH =
            Paths.get(kerberosConfPath, DEFAULT_KERBEROS_CONFIG_FILE).toString();
    private String loginContextName;
    private String targetSPN;

    private String keytabPath;

    private String clientPrincipalValue;

    private GSSManager gssManager = GSSManager.getInstance();

    public String getTargetSPN() {

        return targetSPN;
    }

    public void setTargetSPN(String targetSPN) {

        this.targetSPN = targetSPN;
    }

    public String getLoginContextName() {

        return loginContextName;
    }

    public void setLoginContextName(String loginContextName) {

        this.loginContextName = loginContextName;
    }

    @Override
    public boolean handleRequest(MessageContext messageContext) {

        log.info("krb5 debug logs enabled.");

        log.info("AAAAAAAAAAAAAAAA loginContextName:" + this.loginContextName);
        log.info("BBBBBBBBBBBBBBBB targetSPN:" + this.targetSPN);

        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("sun.security.jgss.debug", "true");

        //reset the context
        //Configuration.setConfiguration(null);
        //System.setProperty(JAAS_CONFIG_PROPERTY,
        //new File(DEFAULT_LOGIN_CONFIG_FILE_PATH).getAbsolutePath());

        //Evaluate values
        extractDataFromLoginConf();

        //Set kerberos configurations.
        System.setProperty(KerberosConstants.KERBEROS_CONFIG_PROPERTY,
                new File(DEFAULT_KERBEROS_CONFIG_PATH).getAbsolutePath());
        //setKerberosConfigurations();

        log.info("GGGGGGGGGGGGGGGGGGGGGGG-clientPrincipalValue:" + this.clientPrincipalValue);

        log.info("FFFFFFFFFFFFFFFFFFFFF-keytabPath:" + this.keytabPath);
        //Create Kerberos token and set to the message context header.
        GSSContext gssContext = null;
        GSSName serverName;

        try {
            Oid mechanismOId = new Oid(SPNEGO_BASED_OID);
            setJASSConfiguration();
            GSSCredential gssCredentials =
                    createClientCredentials(mechanismOId);
            //GSSCredential gssCredentials = createCredentials(mechanismOId);
            serverName = gssManager.createName(targetSPN, GSSName.NT_USER_NAME);
            gssContext =
                    gssManager.createContext(serverName.canonicalize(mechanismOId), mechanismOId, gssCredentials, GSSContext.DEFAULT_LIFETIME);
            byte[] token = new byte[0];
            byte[] serviceTicket = gssContext.initSecContext(token, 0,
                    token.length);

            //Add authorization header to the message context.
            if (serviceTicket != null) {
                setAuthorizationHeader((Axis2MessageContext) messageContext,
                        serviceTicket);
            } else {
                log.error("Unable to get the Kerberos service ticket.");
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            if (gssContext != null) {
                try {
                    gssContext.dispose();
                } catch (GSSException e) {
                    log.warn("Error while disposing GSS Context", e);
                }
            }
        }

        return true;
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {

        return true;
    }

    /**
     * Set the authorization header to the message context.
     *
     * @param synCtx        message context.
     * @param serviceTicket Kerberos ticket.
     * @throws UnsupportedEncodingException on error while encrypting the token.
     */
    private void setAuthorizationHeader(Axis2MessageContext synCtx,
                                        byte[] serviceTicket) throws UnsupportedEncodingException {

        org.apache.axis2.context.MessageContext msgCtx =
                synCtx.getAxis2MessageContext();
        Map<String, Object> headerProp = new HashMap<>();
        headerProp.put(HttpHeaders.AUTHORIZATION,
                KerberosConstants.NEGOTIATE + " " + new String(Base64.encodeBase64(serviceTicket), "UTF-8"));
        msgCtx.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headerProp);

        Map<String, String> headers =
                (Map<String, String>) msgCtx.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        ConcurrentHashMap<String, Object> headerProperties =
                new ConcurrentHashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            headerProperties.put(entry.getKey(), entry.getValue());
        }
        headerProperties.put(HttpHeaders.AUTHORIZATION,
                KerberosConstants.NEGOTIATE + " " + new String(Base64.encodeBase64(serviceTicket), UTF8));
        msgCtx.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headerProperties);
    }

    /**
     * Extracts data from login conf and sets the values
     */
    private void extractDataFromLoginConf() {

        //Read configuration again if type is keytab and config is not
        // configFile
        //Configuration.setConfiguration(null);
        //File file = new File(DEFAULT_LOGIN_CONFIG_FILE_PATH);
        //System.setProperty(JAAS_CONFIG_PROPERTY, file.getAbsolutePath());

        //reset the context
        Configuration.setConfiguration(null);
        System.setProperty(KerberosConstants.LOGIN_CONFIG_PROPERTY,
                new File(DEFAULT_LOGIN_CONFIG_FILE_PATH).getAbsolutePath());
        log.info("DEFAULT_LOGIN_CONFIG_FILE_PATH:" + DEFAULT_LOGIN_CONFIG_FILE_PATH + ":" + new File(DEFAULT_LOGIN_CONFIG_FILE_PATH).getAbsolutePath());
        log.info("getLoginContextName:" + getLoginContextName());
        log.info("targetSPN:" + targetSPN);
        AppConfigurationEntry entries[] =
                Configuration.getConfiguration().getAppConfigurationEntry(getLoginContextName());
        if (entries != null && entries.length != 0) {
            Map<String, ?> options = entries[0].getOptions();
            //Evaluate and set the values for username, password and keytab
            // elements
            log.info("DDDDDDDDDDDDDDDDDDDDDD Entering Entries");
            //Set username.
            this.clientPrincipalValue = options.get("principal").toString();

            //Set keytab path.
            this.keytabPath = options.get("keyTab").toString();
        } else {
            log.info("NOOOOOOOOOOOO Entries");
        }
    }

    private void setKerberosConfigurations() {

        File file = new File(DEFAULT_KERBEROS_CONFIG_PATH);
        if (file.exists()) {
            System.setProperty(KerberosConstants.KERBEROS_CONFIG_PROPERTY,
                    file.getAbsolutePath());
        }
    }

    /**
     * Create GSSCredential for the subject.
     *
     * @param mechanismOId Oid for the mechanism.
     * @return GSSCredential.
     * @throws LoginException
     * @throws PrivilegedActionException
     * @throws GSSException
     */
    private GSSCredential createCredentials(Oid mechanismOId) throws LoginException, PrivilegedActionException, GSSException {

        setJASSConfiguration();
        return createClientCredentials(mechanismOId);
    }

    /**
     * Create GSSCredential for the user.
     * <p>
     * .
     *
     * @param mechanismOId Oid for the mechanism.
     * @return GSSCredential.
     * @throws LoginException
     * @throws PrivilegedActionException
     * @throws GSSException
     */
    private GSSCredential createClientCredentials(final Oid mechanismOId) throws LoginException, PrivilegedActionException, GSSException {

        LoginContext loginContext;
        loginContext = new LoginContext(loginContextName);
        loginContext.login();
        log.info("Pre-authentication successful for with Kerberos Server.");

        // Create client credentials from pre authentication with the AD
        final GSSName clientName = gssManager.createName(clientPrincipalValue
                , GSSName.NT_USER_NAME);
        final PrivilegedExceptionAction<GSSCredential> action =
                new PrivilegedExceptionAction<GSSCredential>() {
            public GSSCredential run() throws GSSException {

                return gssManager.createCredential(clientName.canonicalize(mechanismOId), GSSCredential.DEFAULT_LIFETIME, mechanismOId, GSSCredential.INITIATE_ONLY);
            }
        };

        //  if (log.isDebugEnabled()) {
        Set<Principal> principals = loginContext.getSubject().getPrincipals();
        String principalName = null;
        if (principals != null) {
            principalName = principals.toString();
        }
        log.info("Creating gss credentials as principal : " + principalName);
        // }
        return Subject.doAs(loginContext.getSubject(), action);
    }

    /**
     * Set JASS configuration with the principal and keyTab.
     */
    private void setJASSConfiguration() {

        Map<String, Object> optionSet = new HashMap<>();

        System.setProperty(KerberosConstants.LOGIN_CONFIG_PROPERTY,
                new File(DEFAULT_LOGIN_CONFIG_FILE_PATH).getAbsolutePath());

        AppConfigurationEntry[] entries =
                Configuration.getConfiguration().getAppConfigurationEntry(loginContextName);

        if (entries != null && entries.length != 0) {
            Map<String, ?> options = entries[0].getOptions();
            for (String s : options.keySet()) {
                optionSet.put(s, options.get(s));
            }
        }

        optionSet.put(IS_INITIATOR, "true");
        optionSet.put(PRINCIPAL, clientPrincipalValue);
        optionSet.put(USE_KEYTAB, "true");
        //File keyTabFile = new File(keytabPath);
        log.info("keytabPath:" + keytabPath);
        optionSet.put(KEYTAB, new File(keytabPath).getAbsolutePath());
        optionSet.put(DEBUG, "true");

        final Map<String, Object> finalOptionSet = optionSet;
        Configuration.setConfiguration(new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

                return new AppConfigurationEntry[]{new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED
                        , finalOptionSet)};
            }
        });
    }

}
