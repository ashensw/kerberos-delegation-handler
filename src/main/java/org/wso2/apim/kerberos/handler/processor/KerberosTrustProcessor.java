package org.wso2.apim.kerberos.handler.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.wso2.apim.kerberos.handler.utils.KerberosConstants;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;

public class KerberosTrustProcessor {

    private static final Log log = LogFactory.getLog(KerberosTrustProcessor.class);
    private final Subject selfSubject;
    private final Oid spnegoOid;

    private GSSManager gssManager = GSSManager.getInstance();

    public KerberosTrustProcessor(Subject selfSubject) throws GSSException {
        this.selfSubject = selfSubject;
        this.spnegoOid = new Oid(KerberosConstants.SPNEGO_BASED_OID);
    }


    public byte[] trust(String targetSPN) throws Exception {
        GSSCredential trustCredential = null;
        GSSContext context = null;
        try {
            trustCredential = getCredential();
            context = startAsClient(targetSPN, trustCredential);
            return context.initSecContext(new byte[0], 0, 0);
        } finally {
            if (context != null) {
                try {
                    context.dispose();
                } catch (GSSException e) {
                    // ignore
                }
            }
            if (trustCredential != null) {
                try {
                    trustCredential.dispose();
                } catch (GSSException e) {
                    // ignore
                }
            }
        }
    }


    private GSSCredential getCredential() throws Exception {


        try {
            final GSSName clientName =
                    gssManager.createName(selfSubject.getPrincipals().iterator().next().getName(),
                            GSSName.NT_USER_NAME);

            final PrivilegedExceptionAction<GSSCredential> action = new PrivilegedExceptionAction<GSSCredential>() {
                public GSSCredential run() throws GSSException {

                    return gssManager.createCredential(clientName.canonicalize(spnegoOid),
                            GSSCredential.DEFAULT_LIFETIME, spnegoOid, GSSCredential.INITIATE_ONLY);
                }
            };

            return Subject.doAs(selfSubject, action);
        } catch (PrivilegedActionException e) {
            throw new Exception("Cannot create GSS credential from client's Kerberos ticket.", e.getException());
        }
    }

    private GSSContext startAsClient(String targetSPN, GSSCredential gssCredential) throws Exception {
        PrivilegedExceptionAction<GSSContext> action = new PrivilegedExceptionAction<GSSContext>() {
            @Override
            public GSSContext run() throws Exception {
                GSSName serverName = gssManager.createName(targetSPN, GSSName.NT_USER_NAME);
                //gssContext.requestMutualAuth(true);
                //gssContext.requestCredDeleg(true);
                return gssManager
                        .createContext(serverName.canonicalize(spnegoOid), spnegoOid, gssCredential,
                                GSSContext.DEFAULT_LIFETIME);
            }
        };
        try {
            GSSName serverName = gssManager.createName(targetSPN, GSSName.NT_USER_NAME);

            return gssManager.createContext(serverName.canonicalize(spnegoOid),
                    spnegoOid, gssCredential, GSSContext.DEFAULT_LIFETIME);
        } catch (GSSException e) {
            throw new Exception(
                    "Cannot create GSS context for '" + targetSPN + "' SPN using '" + gssCredential + "'.");
        }
    }
}
