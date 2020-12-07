package org.wso2.apim.kerberos.handler.utils;

import org.apache.http.HttpHeaders;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class KerberosUtils {

    public static boolean setAsUnAuthorizedUser(Map headersMap,
                                    MessageContext messageContext, byte[] serverToken) {
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext)
                .getAxis2MessageContext();
        String outServerTokenString = null;
        headersMap.clear();
        try {
            if (serverToken != null) {
                outServerTokenString = Base64.getEncoder().encodeToString(serverToken);
            }
            axis2MessageContext.setProperty("HTTP_SC", "401");
            if (outServerTokenString != null) {
                headersMap.put(KerberosConstants.AUTHENTICATE_HEADER,
                        KerberosConstants.NEGOTIATE + " " + outServerTokenString);
            } else {
                headersMap.put(KerberosConstants.AUTHENTICATE_HEADER, KerberosConstants.NEGOTIATE);
            }
            axis2MessageContext.setProperty("NO_ENTITY_BODY", new Boolean("true"));
            messageContext.setProperty("RESPONSE", "true");
            messageContext.setTo(null);
            Axis2Sender.sendBack(messageContext);
            return false;

        } catch (Exception e) {
            return false;
        }
    }

    public static String getKerberosHeader(Map headers) {
        return (String) headers.get(HttpHeaders.AUTHORIZATION);
    }

    public static Map getTransportHeaders(MessageContext messageContext) {
        return (Map) ((Axis2MessageContext) messageContext).getAxis2MessageContext().
                getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
    }

    /**
     * Set the authorization header to the message context.
     *
     * @param synCtx        message context.
     * @param serviceTicket Kerberos ticket.
     * @throws UnsupportedEncodingException on error while encrypting the token.
     */
    public static void setKerberosTokenToHeader(Axis2MessageContext synCtx,
                                        byte[] serviceTicket) throws UnsupportedEncodingException {

        org.apache.axis2.context.MessageContext msgCtx = synCtx.getAxis2MessageContext();
        
        Map<String, String> headers = (Map<String, String>) msgCtx.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        ConcurrentHashMap<String, Object> headerProperties = new ConcurrentHashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            headerProperties.put(entry.getKey(), entry.getValue());
        }
        headerProperties.put(HttpHeaders.AUTHORIZATION, KerberosConstants.NEGOTIATE + " " +
                Base64.getEncoder().encodeToString(serviceTicket));
        msgCtx.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headerProperties);
    }


}
